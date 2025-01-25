#!/bin/bash
netstat -ant | grep ESTABLISHED | grep ':80 ' | wc -l
