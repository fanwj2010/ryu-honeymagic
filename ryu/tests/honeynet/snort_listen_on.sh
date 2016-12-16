#!/bin/bash
snort -i Net1-snort -A unsock -l /tmp -c /etc/snort/snort.conf
