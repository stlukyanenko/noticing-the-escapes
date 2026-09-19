import json,re,csv
revs=json.load(open('revs_all.json'))
cm=[o for o in revs if o['fam'] in ('datausa-cashiers-masters',)]
cb=[o for o in revs if o['fam']=='datausa-cashiers-bachelors']
gro=[o for o in revs if o['fam']=='datausa-grocery-workforce']
con=[o for o in revs if o['fam']=='datausa-construction-workforce']
cip=[r['CIP2'] for r in json.load(open('cm2014.json'))['data']]
states=[r['State'] for r in json.load(open('gro2014.json'))['data']]
# short aliases used in text
cipal={'Education':'Education','Business':'Business','Social Sciences':'Social Sciences','Visual & Performing Arts':'Visual & Performing Arts','Psychology':'Psychology','Health':'Health','Biology':'Biology','Engineering':'Engineering','English':'English','Communications':'Communications'}
rows=[]
def scan(items,names,fam):
    seen=set()
    for o in items:
        b=o['body']
        for n in names:
            for m in re.finditer(re.escape(n)+r'[^0-9\n]{0,40}?([0-9][0-9,]{2,})',b):
                v=m.group(1).rstrip(',')
                key=(fam,n,v)
                if key in seen: continue
                seen.add(key)
                rows.append(dict(fam=fam,param=n,claimed=v,page=o['page'],label=o['label'],time=o['time']))
scan(cm,cip,'datausa-cashiers-masters')
scan(cb,cip,'datausa-cashiers-bachelors')
scan(gro,states,'datausa-grocery-workforce')
scan(con,states,'datausa-construction-workforce')
print(len(rows))
for r in rows: print(r['fam'],'|',r['param'],'|',r['claimed'],'|',r['label'])
json.dump(rows,open('claims.json','w'),indent=1)
