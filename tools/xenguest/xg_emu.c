#include <semaphore.h>
#include <time.h>

#include <libempserver.h>
#include "xg_internal.h"
#include INCLUDE_JSON_H

static sem_t sem_stopped;
static int live_stage = XGS_POLICY_CONTINUE_PRECOPY;
static bool pv_mode;

static struct emu_client progress_cli = { .num = -1 };
static int last_iter;
static uint64_t last_sent;
static int stream_fd = -1;

static int arg_store_port = -1;
static int arg_console_port = -1;

/* timeout in seconds */
#define COMMAND_TIMEOUT (60 * 2)

/* Called for mid-iteration progress update */
void send_emu_progress(unsigned long done, unsigned long total)
{
    static struct timespec lastprog;

    struct timespec curtime;

    clock_gettime(CLOCK_MONOTONIC, &curtime);

    if ( progress_cli.num >= 0 )
    {
        if ( done == 0 || done == total )
        {
            lastprog = curtime;
        }
        else if ( ts_delta_us(&curtime, &lastprog) > MSEC(500) )
        {
            /* Don't send dirty_count, is out of date */
            emp_send_event_migrate_progress(progress_cli, last_sent + done, -1, last_iter);
            lastprog = curtime;
        }
    }
}

static void do_cmd_progress(emp_call_args *args)
{
    progress_cli = args->cli;
    xg_info("setting progress_cli to %d", progress_cli.num);
    emp_send_return(args->cli, NULL);
}

static int running = 1;

static void do_cmd_quit(emp_call_args *args)
{
    emp_send_return(args->cli, NULL);
    running = 0;
}

static void abort_all(void)
{
    live_stage = XGS_POLICY_ABORT;
    /* post to sem, incase we are waiting */
    sem_post(&sem_stopped);
}

static void do_abort(emp_call_args *args)
{
    xg_err("Received abort command!");
    abort_all();
    emp_send_return(args->cli, NULL);
}

static void do_ignore(emp_call_args *args)
{
    emp_send_return(args->cli, NULL);
}

static void do_migrate_init(emp_call_args *args)
{
    stream_fd = args->fd;
    emp_send_return(args->cli, NULL);
    sem_init(&sem_stopped, 0, 0);
}

int emu_suspend_callback(void *data)
{
    int r;

    xg_info("waiting for suspend");
    r = sem_wait(&sem_stopped);
    if ( live_stage == XGS_POLICY_ABORT )
    {
        xg_info("Ignoring libxc suspend request due to abort");
        return 0;
    }

    xg_info("suspend was received");
    return 1;
}

/* Monitor process */
int xenguest_precopy_policy(struct precopy_stats stats, void *user)
{
    int stop_decision = live_stage;
    int r = 0;

    if ( stats.dirty_count >= 0 )
    {
        struct emu_client *cli = user;

        last_sent = stats.total_written;
        last_iter = stats.iteration;

        xg_info("Checking live policy.  %ld / %ld for %d",
                stats.dirty_count, stats.total_written, stats.iteration);
        r = emp_send_event_migrate_progress(*cli, stats.total_written,
                                            stats.dirty_count,
                                            stats.iteration);
    }

    if ( stop_decision )
        xg_info("passing down stop message");
    else if ( stats.dirty_count == 0 )
    {
        xg_info("No dirty pages, finishing migration");
        stop_decision = XGS_POLICY_STOP_AND_COPY;
    }

    return stop_decision;
}

static void do_migrate_live(emp_call_args *args)
{
    /* unlock the global lock and go ahead */
    emp_unlock();

    emp_send_return(args->cli, NULL);

    emu_stub_xc_domain_save(stream_fd, &args->cli, XCFLAGS_LIVE);
    xg_info("Finished, send complete");
    if ( progress_cli.num >= 0 )
        emp_send_event_migrate_completed(progress_cli, migration_success);
    else
        xg_info("No cli watching");

}

static void do_migrate_nonlive(emp_call_args *args)
{
    /* unlock the global lock and go ahead */
    emp_unlock();

    emp_send_return(args->cli, NULL);

    emu_stub_xc_domain_save(stream_fd, &args->cli, 0);
    xg_info("Finished, send complete");
    emp_send_event_migrate_completed(args->cli, migration_success);

    if ( progress_cli.num >= 0 )
        emp_send_event_migrate_completed(progress_cli, migration_success);
    else
        xg_info("No cli watching");
}

static void do_migrate_paused(emp_call_args *args)
{
    xg_info("Received paused message");
    emp_send_return(args->cli, NULL);
    sem_post(&sem_stopped);
}

static void do_migrate_pause(emp_call_args *args)
{
    xg_info("Received pause message");
    emp_send_return(args->cli, NULL);
    live_stage = XGS_POLICY_STOP_AND_COPY;
}

static void do_cmd_restore(emp_call_args *args)
{
    unsigned long store_mfn = 0, console_mfn = 0;
    char buf[64];

    if ( domid == -1 || stream_fd == -1 || arg_store_port == -1 ||
         arg_console_port == -1 )
    {
        xg_err("xenguest: missing command line options\n");
        emp_send_error(args->cli, "Missing options");
        return;
    }
    emp_unlock();

    emp_send_return(args->cli, NULL);

    stub_xc_domain_restore(stream_fd, arg_store_port, arg_console_port, !pv_mode,
                           &store_mfn, &console_mfn);

    xg_info("Restore complete, send result");
    snprintf(buf, sizeof(buf), "%lu %lu", store_mfn, console_mfn);

    if ( progress_cli.num >= 0 )
        emp_send_event_migrate_completed_result(progress_cli, buf);
    if ( progress_cli.num != args->cli.num )
        emp_send_event_migrate_completed_result(args->cli, buf);
    xg_info("All done");
}

enum arg_type
{
    int_type,
    str_type,
    bool_type,
};

struct arg_list
{
    char *name;
    enum arg_type atype;
    union
    {
        int *a_int;
        bool *a_bool;
        char **a_str;
    };
};

const static struct arg_list setable_args[] = {
    {"store_port",   int_type,  .a_int = &arg_store_port},
    {"console_port", int_type,  .a_int = &arg_console_port},
    {"pv",           bool_type, .a_bool = &pv_mode},
    {"vgpu",         bool_type, .a_bool = &opt_vgpu},
    {}
};

void do_cmd_set_args(emp_call_args *args)
{
    json_object *jobj = args->cmd_args;
    int ival;
    char *str_end;
    const char *val;
    int bad = 0;
    int i;
    json_object_iter iter;

    if ( jobj == NULL )
    {
        xg_err("set_args called without any args");
        emp_send_error(args->cli, "No Args");
        return;
    }

    json_object_object_foreachC(jobj, iter)
    {
        if ( json_object_get_type(iter.val) != json_type_string )
        {
            xg_err("expecting only string arguments.  (%s)", iter.key);
            bad = 1;
            continue;
        }
        val = json_object_get_string(iter.val);

        for ( i = 0; setable_args[i].name != NULL; i++ )
        {
            if ( strcmp(setable_args[i].name, iter.key) == 0 )
            {
                switch ( setable_args[i].atype )
                {
                case int_type:
                    ival = strtol(val, &str_end, 10);
                    if ( *str_end != '\0' )
                    {
                        xg_err("Bad args %s = %s", iter.key, val);
                        bad = 1;
                    }
                    else
                        *(setable_args[i].a_int) = ival;
                    break;

                case str_type:
                    *(setable_args[i].a_str) = strdup(val);
                    break;

                case bool_type:
                    if ( strcmp(val, "true") == 0 )
                        *(setable_args[i].a_int) = 1;
                    else if ( strcmp(val, "false") == 0 )
                        *(setable_args[i].a_int) = 0;
                    else
                    {
                        xg_err("Bad args %s = %s", iter.key, val);
                        bad = 1;
                    }
                    break;
                }
                break;
            }
        }
        if ( setable_args[i].name == NULL )
        {
            xg_err("Unknown arg: %s", iter.key);
            bad = 1;
        }
    }
    if ( bad )
        emp_send_error(args->cli, "Bad Args");
    else
        emp_send_return(args->cli, NULL);
}

/* const */ static struct command_actions actions[] = {
    {cmd_track_dirty,      &do_ignore, 0 },
    {cmd_migrate_abort,    &do_abort, 0 },
    {cmd_migrate_init,     &do_migrate_init, 0 },
    {cmd_migrate_live,     &do_migrate_live, 1 },
    {cmd_migrate_pause,    &do_migrate_pause, 0 },
    {cmd_migrate_paused,   &do_migrate_paused, 0 },
    {cmd_migrate_progress, &do_cmd_progress,  0 },
    {cmd_migrate_nonlive,  &do_migrate_nonlive, 1},
    {cmd_restore,          &do_cmd_restore, 1 },
    {cmd_set_args,         &do_cmd_set_args, 0},
    {cmd_quit,             &do_cmd_quit,      0 }
};

static void emp_log(enum emp_log_level level, const char *msg)
{
    if ( level == emp_level_err )
        xg_err("libempserver: %s", msg);
    else if ( level == emp_level_warn || level == emp_level_info )
        xg_info("libempserver: %s", msg);
    else if ( (opt_flags & XCFLAGS_DEBUG) )
        xg_info("libempserver:debug: %s", msg);
}

#define EMU_NAME     "xenguest"

void emp_do_listen(void)
{
    struct emp_sock_inf *cs_inf;
    int rc;
    char fname[PATH_MAX];
    int r;
    struct timespec act_time;

    emp_set_log_cb(emp_log);

    r = emp_get_default_path(fname, sizeof(fname), EMU_NAME, domid);
    if ( r < 0 )
    {
        xg_err("Failed to get control path. err=%d", errno);
        return;
    }

    if ( r > (int)sizeof(fname) )
    {
        xg_err("Control path too long.");
        return;
    }

    r = emp_sock_init(fname, &cs_inf, actions);
    if ( r )
    {
        xg_err("control socket failed");
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &act_time);

    printf("Ready\n");

    while ( running )
    {
        fd_set          rfds;
        fd_set          wfds;
        fd_set          xfds;
        int             nfds;
        int             num_clients;
        struct timeval  tv;

        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_ZERO(&xfds);
        tv.tv_sec = 30;
        tv.tv_usec = 0;

        nfds = emp_select_fdset(cs_inf, &rfds, &num_clients);
        nfds++;
        rc = select(nfds, &rfds, &wfds, &xfds, &tv);

        if ( rc == 0 && num_clients == 0 )
        {
            struct timespec cur_time;
            uint64_t timediff;

            clock_gettime(CLOCK_MONOTONIC, &cur_time);
            timediff = ts_delta_us(&cur_time, &act_time);

            if ( timediff > SEC(COMMAND_TIMEOUT) )
            {
                xg_err("Control timeout");
                abort_all();
                break;
            }
        }
        else
            clock_gettime(CLOCK_MONOTONIC, &act_time);

        if ( rc < 0 && errno != EINTR )
            break;

        if ( rc > 0 )
        {
            rc = emp_select_fdread(cs_inf, &rfds, rc);
            if ( rc > 0 )
                xg_info("Warning: there were unclaimed fds");
        }
    }
    /* wait for any threads to finish */
    emp_sock_close(&cs_inf);
    unlink(fname);
}
