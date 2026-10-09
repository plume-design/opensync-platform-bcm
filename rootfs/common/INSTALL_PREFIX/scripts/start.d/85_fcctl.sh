#!/bin/sh

# Set fc software deferral limit
/bin/fcctl config --sw-defer 15
# Set fc acceleration mode to L3
/bin/fcctl config --accel-mode 0
/bin/fcctl enable

