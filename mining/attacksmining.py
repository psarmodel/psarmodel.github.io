import pandas as pd
import numpy as np
from mlxtend.frequent_patterns import apriori, association_rules
from mlxtend.preprocessing import TransactionEncoder



'''load data'''
df = pd.read_csv("attacksdataset.csv", names = ['data'], sep = ',')
file =df.head()

'''split lines using , '''
data = list(df["data"].apply(lambda x:x.split(",") ))

'''tranform a list to 0/1 true/false'''
a = TransactionEncoder()
a_data = a.fit(data).transform(data)
df = pd.DataFrame(a_data,columns=a.columns_)
df = df.replace(False,0)


'''run apriori'''

df = apriori(df, min_support = 0.1, use_colnames = True, verbose = 1)



'''interpretation'''
'''I chose the 60% minimum confidence value. In other words, when element X is selected, we can say that the selection of element Y is 60% or more.'''
rules = association_rules(df, metric = "confidence", min_threshold = 0.01)

print (rules)



'''print the attacks'''
for index, row in rules.iterrows():
    print(list(row['antecedents']), "->", list(row['consequents']))
