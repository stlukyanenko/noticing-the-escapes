import json,csv,re
claims=json.load(open('claims.json'))
URL={
 'datausa-cashiers-masters':"https://api.datausa.io/tesseract/data.jsonrecords?cube=pums_5&drilldowns=CIP2,Year&measures=Total%20Population&include=Detailed%20Occupation:412010;Workforce%20Status:true;Degree:22;Year:2014",
 'datausa-cashiers-bachelors':"https://api.datausa.io/tesseract/data.jsonrecords?cube=pums_5&drilldowns=CIP2,Year&measures=Total%20Population&include=Detailed%20Occupation:412010;Workforce%20Status:true;Degree:21;Year:2015",
 'datausa-grocery-workforce':"https://api.datausa.io/tesseract/data.jsonrecords?cube=pums_5&drilldowns=State,Year&include=Industry%20Group:4451;Workforce%20Status:true;Year:2014&locale=en&measures=Total%20Population",
 'datausa-construction-workforce':"https://api.datausa.io/tesseract/data.jsonrecords?cube=pums_5&drilldowns=State,Year&include=Industry%20Sector:23;Workforce%20Status:true;Year:2016,2018&locale=en&measures=Total%20Population",
}
def tab(f,key):
    d=json.load(open(f))['data']; t={}
    for r in d: t.setdefault(r[key],[]).append(r['Total Population'])
    return t
T={'datausa-cashiers-masters':tab('cm2014.json','CIP2'),
   'datausa-cashiers-bachelors':tab('cb2015.json','CIP2'),
   'datausa-grocery-workforce':tab('gro2014.json','State'),
   'datausa-construction-workforce':tab('con.json','State')}
VINT={'datausa-cashiers-masters':'Year:2014 in URL; response Year=2014',
      'datausa-cashiers-bachelors':'Year:2015 in URL; response Year=2015',
      'datausa-grocery-workforce':'Year:2014 in URL; response Year=2014',
      'datausa-construction-workforce':'Year:2016,2018 (two values per state); response matches'}
rows=[]
for c in claims:
    v=float(c['claimed'].replace(',',''))
    if c['claimed'].replace(',','') in ('2014','2015','2016','2017','2018'):
        c['status']='EXCLUDED_year_token'; c['today']=''; rows.append(c); continue
    truth=T[c['fam']].get(c['param'],[])
    if not truth: c['status']='NOT_REDERIVABLE'; c['today']=''
    else:
        c['today']='/'.join(str(int(x)) for x in truth)
        if any(abs(v-x)<0.5 for x in truth): c['status']='EXACT'
        elif any(abs(v-x)/x<=0.01 for x in truth): c['status']='ROUNDING'
        else: c['status']='WRONG'
    c['url']=URL[c['fam']]; c['vintage']=VINT[c['fam']]
    rows.append(c)
good=[r for r in rows if r['status']!='EXCLUDED_year_token']
with open('were_they_right_pairs.csv','w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=['fam','param','claimed','today','status','url','vintage','page','label','time'])
    w.writeheader()
    for r in good: w.writerow({k:r.get(k,'') for k in w.fieldnames})
import collections
print(collections.Counter(r['status'] for r in good))
print('total pairs',len(good))
for r in good: print(r['status'],'|',r['fam'],'|',r['param'],'|',r['claimed'],'->',r['today'],'|',r['label'])
