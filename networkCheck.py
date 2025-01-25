import subprocess
import sys
import time
import csv
argv = sys.argv
timer=0
Report = argv[1] + '.csv'
result = open(Report,'w')
writer = csv.writer(result)
writer.writerow(['Time','ChildProcess','Connection'])

while True:
    ProcessCount = subprocess.check_output(['sh','ProcessCount.sh']).decode(encoding='UTF-8').strip()
    ConnectionCount = subprocess.check_output(['sh','ConnectionCount.sh']).decode(encoding='UTF-8').strip()
    writer.writerow([timer,ProcessCount,ConnectionCount])
    print('Time {}: ChildProcess: {}     Connection: {}'.format(timer,ProcessCount,ConnectionCount))
    time.sleep(1)
    timer+=1
    if(timer == int(argv[2])+1):
        break

