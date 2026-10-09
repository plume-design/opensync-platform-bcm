#!/bin/sh

# This prevents garbage from `nvram commit` from polluting the kv store
nvram getall \
    | awk '/^wl/ || /^wps/ || /^lan/ || /^nas_/' \
    | awk '!(/^wl._dis_ch_grp/ || /^wl._radarthrs/ || /^wl_mlo_config/ || /^wl_mlo_enable_vap_index/)' \
    | cut -d= -f1 \
    | sed 's/^/unset /' \
    | xargs -r -n 1024 nvram

