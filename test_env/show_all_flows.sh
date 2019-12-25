#!/bin/bash

echo "====== SLG1 ======"
no_proxy=* ../ofctl_script/show_flow -d 1
echo "====== SLG2 ======"
no_proxy=* ../ofctl_script/show_flow -d 2
echo "====== SLG3 ======"
no_proxy=* ../ofctl_script/show_flow -d 3
