from lnd_rest import *
import code
import pandas

pandas.set_option('display.max_colwidth', None)
pandas.set_option('display.max_rows', None)


def rebalance_script():
	a = listChannels()
	a = a[a['active'] == True]
	pl = []
	bcount = 0
	while len(a[a['local_balance'] < 500000]) > 0:
		a = listChannels()
		a = a[a['active'] == True]
		taker = a['tobalance'].idxmax()
		giver = a['tobalance'].idxmin()
		oid = a.loc[giver].chan_id
		pk = a.loc[taker].remote_pubkey
		# Divide it down to smaller chunks for cheaper fees
		pay_piece = int(a.loc[taker].tobalance/3)
		if pay_piece < 75000:
			pay_piece = int(a.loc[taker].tobalance)
		print(f'Sending {pay_piece} from {a.loc[giver].alias} to {a.loc[taker].alias}!')
		result = rebalance(pay_piece,oid,pk,5000,force=True)
		pl.append(result)
		bcount += 1
		print(f'Rebalanced {bcount} times!')
	return pl

def inflows():
	a = getForwards(60)
	in_oids = a['chan_id_in'].unique()
	df = pandas.DataFrame()
	for edge in in_oids:
		try:
			df = df.append(getChanPolicy(edge))
		except Exception as e:
			print(f'Edge Not Found: {e}')
	df = df.reset_index()
	df = df.drop(['index'],axis=1)
	return df[df['pubkey'] != getMyPk()]


def outflows():
	a = getForwards(60)
	out_oids = a['chan_id_out'].unique()
	df = pandas.DataFrame()
	for edge in out_oids:
		try:
			df = df.append(getChanPolicy(edge))
		except Exception as e:
			print(f'Edge Not Found: {e}')
	df = df.reset_index()
	df = df.drop(['index'],axis=1)
	return df[df['pubkey'] != getMyPk()]

def flowsort():
	c = listChannels()
	fin = inflows()
	fout = outflows()
	in_nodes = set(fin.pubkey)
	out_nodes = set(fout.pubkey)
	routing_nodes = in_nodes.intersection(out_nodes)
	in_nodes = in_nodes - routing_nodes
	out_nodes = out_nodes - routing_nodes
	c[c['remote_pubkey'].isin(list(routing_nodes)) ]
	return in_nodes, routing_nodes, out_nodes


def rebalancePartners():
	partners = []
	mypk = getMyPK()
	hop1_partners = getNodeChannels(mypk)
	count = 0
	for z in hop1_partners.iterrows():
		hop1_pk = z[1].item()
		hop2_partners = getNodeChannels(hop1_pk)
		for y in hop2_partners.iterrows():
			hop2_pk = y[1].item()
			hop3_partners = getNodeChannels(hop2_pk)
			for x in hop3_partners.iterrows():
				hop3_pk = x[1].item()
				count += 1
				print(f'Searched {count} nodes')
				if hop3_pk == mypk:
					partners.append((hop1_pk, hop2_pk, hop3_pk))
	return partners


if __name__ == "__main__":
	code.interact(local=locals())