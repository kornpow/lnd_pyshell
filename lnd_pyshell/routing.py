

# def getForwards(start,end):
def getForwards(days_past=30):
    start = int((datetime.now() - timedelta(days=days_past)).timestamp())
    end = int(datetime.now().timestamp())
    data = {"start_time": start, "end_time": end, "num_max_events": 10000}
    url = "/v1/switch"
    lnreq = sendPostRequest(url, data)
    fwd_frame = pandas.DataFrame(lnreq["forwarding_events"])
    # Convert Timestamp to nice datetime
    fwd_frame["dt"] = fwd_frame["timestamp"].apply(
        lambda x: datetime.fromtimestamp(int(x))
    )
    fwd_frame["dts"] = fwd_frame.dt.astype("str")
    print(
        f'Number of Satoshi Made This Month: {pandas.to_numeric(fwd_frame["fee_msat"]).sum()/1000}!'
    )
    print(
        f'AVG Number of Satoshi Made Per Day: {pandas.to_numeric(fwd_frame["fee_msat"]).sum()/1000/days_past}!'
    )
    # TODO keep track of rebalance fees
    # a['settle_date_h']=a['settle_date_h'].astype('str')
    # a.query(f'settle_date_h.str.contains("2020-11-19")')
    return fwd_frame
    

def fwdsToday(ff):
    fwds = ff.query(f'dts.str.contains("{datetime.now().strftime("%Y-%m-%d")}")').shape[
        0
    ]
    return fwds


def fwdsStats(ff, days_ago=0):
    day_str = (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d")
    day_fwds = ff.query(f'dts.str.contains("{day_str}")')
    day_fwds_count = ff.query(f'dts.str.contains("{day_str}")').shape[0]
    avg_fees = day_fwds.fee_msat.astype("float").mean()
    avg_forward = day_fwds.amt_in.astype("float").mean()
    return {
        "event_day": day_str,
        "count": day_fwds_count,
        "avg_fees": avg_fees,
        "avg_forward": avg_forward,
    }


def fwdByDay(ff, days_past=30):
    # datetime.strptime('2020-04-04','%Y-%m-%d')
    t = datetime.now().date() - timedelta(days_past)
    t.strftime("%Y-%m-%d")
    results = []
    # TODO: look into this logic a bit
    for i in range(0, days_past + 1):
        num_fwds = ff.query(f'dts.str.contains("{t.strftime("%Y-%m-%d")}")').shape[0]
        fees = (
            ff.query(f'dts.str.contains("{t.strftime("%Y-%m-%d")}")')
            .fee_msat.astype("float")
            .sum()
            / 1000
        )
        results.append((t.strftime("%Y-%m-%d"), num_fwds, fees))
        t += timedelta(days=1)
    rframe = pandas.DataFrame(results)
    rframe.columns = ["date", "forwards", "sats_earned"]
    return rframe