### Benchmarks:

```
xakepnz@gcsb tests % python3 benchmarks.py
```

```
Loading import took: 0.04817605018615723
Initialise Attack object (fresh download json) took: 0.46376705169677734
Initialise Attack object (saved json) took: 0.09171009063720703
Iterate over each relationship object took: 0.0002422332763671875
Iterate over each software object took: 0.004894256591796875
Iterate over each software object and jsonify it took: 14.67059588432312
Iterate over each software object and assoc group object took: 0.008013010025024414
Iterate over each software object and assoc technique object took: 0.027391433715820312
Iterate over every software/technique/sub_technique object took: 0.09391307830810547
Iterate over each software group object took: 0.007494211196899414
Iterate over each data source object took: 0.0013051033020019531
Iterate over every data source object and jsonify it: 0.0025207996368408203
Iterate over each data source object and the techniques it took: 0.0024328231811523438
Iterate over each data source/technique/subtechnique objects it took: 0.0022079944610595703
Iterate over each data source object and component took: 0.0014641284942626953
Iterate over every group object took: 0.0015130043029785156
Jsonify every group object took: 1.163365125656128
Iterate over every group software object took: 0.004899024963378906
Iterate over every group technique object took: 0.006133079528808594
Iterate over each technique object took: 0.0021958351135253906
Iterate over each technique/sub_technique object took: 0.004724025726318359
Iterate over each technique/mitigation object took: 0.0052297115325927734
Iterate over each technique/tactic object took: 0.3483388423919678
Iterate over each technique/data source object took: 0.20364809036254883
Iterate over each technique object and jsonify it took: 0.5833890438079834
Iterate over each tactic object took: 0.0011739730834960938
Iterate over each tactic object and jsonify it took: 0.018831968307495117
Iterate over each tactic and technique object took: 0.021281003952026367
Iterate over each sub_technique object took: 0.0024709701538085938
Iterate over each sub_technique/data source object took: 0.38770198822021484
Iterate over each sub_technique/tactic object took: 0.8316378593444824
Iterate over each sub_technique/tactic object took: 0.005716085433959961
Iterate over each sub_technique/tactic object took: 0.00559687614440918
Iterate over each sub_technique/tactic object took: 0.009369134902954102
Iterate over each sub_technique object and jsonify took: 1.256603717803955
Iterate over each sub_technique/mitigation object took: 0.0060312747955322266
Iterate over each mitigation object took: 0.0018689632415771484
Iterate over each mitigation object and jsonify took: 0.9342870712280273
Iterate over each mitigation/technique object took: 0.0031630992889404297
```