# pehash.py 
pehash for PE file, sha1 of PE structural properties.

Implementation of pehash based on algorithm from   
"peHash: A Novel Approach to Fast Malware Clustering"
([html] (https://www.usenix.org/legacy/event/leet09/tech/full_papers/wicherski/wicherski_html/),
 [pdf] (https://www.usenix.org/legacy/event/leet09/tech/full_papers/wicherski/wicherski.pdf))

As far as there are no known source for test/check, include [#totalhash](http://totalhash.com/blog/pehash-source-code/), where implementation looks like completely wrong, [here was assumed](https://github.com/AnyMaster/pehash/wiki), that binary values placed into hash in Big Endian format.

