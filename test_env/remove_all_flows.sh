#!/bin/bash

no_proxy=* ../ofctl_script/del_flow -d 1 -f '{"match":{}}'
no_proxy=* ../ofctl_script/show_flow -d 1
no_proxy=* ../ofctl_script/del_flow -d 2 -f '{"match":{}}'
no_proxy=* ../ofctl_script/show_flow -d 2
no_proxy=* ../ofctl_script/del_flow -d 3 -f '{"match":{}}'
no_proxy=* ../ofctl_script/show_flow -d 3
