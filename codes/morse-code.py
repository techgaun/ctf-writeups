#!/usr/bin/python

# Parse and aggregate file created by sox via the command:
# sox inputfile.ext output.dat

fp = open("output.dat")
data = [int(abs(float(x.split()[1])) > 0.01) for x in fp.readlines()[2:]]
fp.close()

# count all the runs
counts = []
current = -1
count = 0
for i in data:
  if i != current:
    counts.append((current,count))
    current = i
    count = 0
  count += 1

# now remove all short runs, which also removes the -1 row!
counts = [x for x in counts if x[1] >= 15]

# and reaggregate everything
counts2 = []
current = -1
count = 0
for i in counts:
  if i[0] != current:
    counts2.append((current,count))
    current = i[0]
    count = 0
  count += i[1]

mystr = ""
for x in counts2:
  if x[0] == 0:
    if x[1] > 350:
      mystr += " "
  elif x[0] == 1:
    if x[1] > 500:
      mystr += "-"
    else:
      mystr += "."
print mystr
