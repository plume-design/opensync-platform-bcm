#!/bin/sh
# {# jinja-parse #}

echo -n "Configuring BCM debug_monitor... "

# reboot device as recovery
{% if CONFIG_OSP_REBOOT_CLI_OVERRIDE -%}
nvram set "recovery_script={{INSTALL_PREFIX}}/scripts/fw_trap_reboot.sh"
{%- else -%}
nvram set "recovery_script=/sbin/reboot"
{%- endif %}

echo "done."
