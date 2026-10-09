#!/bin/sh
# {# jinja-parse #}

# run a command with increased process priority
# and temporarily elevated system rt_runtime

LOG_NAME="${0##*/}"

log()
{
    logger -s -t "$LOG_NAME" $@
}

perf_runprio_local_restore()
{
    # CS00012394804: revert for ordinary traffic
    pidof sw_gso_0 | xargs -n 1 taskset -p f | log
    pidof sw_gso_1 | xargs -n 1 taskset -p f | log
}


perf_runprio_local_apply()
{
    pidof sw_gso_0 | xargs -n 1 taskset -pc 1 | log
    pidof sw_gso_1 | xargs -n 1 taskset -pc 2 | log
}


