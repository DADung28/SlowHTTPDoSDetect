#!/bin/bash
ps -ef | grep apache2 | grep www-data | grep -v grep | wc -l
