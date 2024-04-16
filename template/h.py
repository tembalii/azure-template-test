import pandas


def lambda_handler(event, context):

    tainted = event['exploit_code']
    s = "encoded-data"
    bytearray().extend(map(ord,string))

    # ruleid: tainted-pandas-hdf-aws-lambda
    pandas.read_hdf(tainted)
    # ruleid: tainted-pandas-hdf-aws-lambda
    pandas.read_hdf(tainted, mode='r', key=None, errors='strict')

    # ok: tainted-pandas-hdf-aws-lambda
    pandas.read_hdf(s)
    # ok: tainted-pandas-hdf-aws-lambda
    pandas.read_hdf(s, mode='r', key=None, errors='strict')
