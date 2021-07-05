#!/bin/sh

# Copyright (c) 2017, Plume Design Inc. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#    3. Neither the name of the Plume Design Inc. nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


# run a command with increased process priority
# and temporarily elevated system rt_runtime

RT_RUNTIME=95000
CHRT_PRIO="-r 5"
SIGNALS="INT HUP TERM EXIT QUIT"

restore_rt_runtime()
{
    RET=$?
    if [ -n "$ORIG_RT_RUNTIME" ]; then
        logger "[$PPID]: $0: restoring sched_rt_runtime to $ORIG_RT_RUNTIME"
        echo "$ORIG_RT_RUNTIME" > /proc/sys/kernel/sched_rt_runtime_us
    fi
    trap - $SIGNALS
    exit $RET
}

# temporarily elevate sched_rt_runtime
ORIG_RT_RUNTIME=$(grep "BRCM_SCHED_RT_RUNTIME=" /etc/build_profile 2>/dev/null | cut -d= -f2)
if [ -n "$ORIG_RT_RUNTIME" -a "$RT_RUNTIME" -gt "$ORIG_RT_RUNTIME" ]; then
    logger "[$PPID]: $0: elevating sched_rt_runtime to $RT_RUNTIME"
    trap restore_rt_runtime $SIGNALS
    echo "$RT_RUNTIME" > /proc/sys/kernel/sched_rt_runtime_us
else
    logger "[$PPID]: $0: WARNING: not changing sched_rt_runtime $ORIG_RT_RUNTIME to $RT_RUNTIME"
fi

# if args start with - pass them to chrt
if [ "${1:0:1}" = "-" ]; then
    CHRT_PRIO=
fi

# run command with increased prio
logger "[$PPID]: $0: /usr/bin/chrt $CHRT_PRIO $*"
/usr/bin/chrt $CHRT_PRIO "$@"

# restore original sched_rt_runtime
restore_rt_runtime
