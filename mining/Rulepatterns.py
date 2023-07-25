import pandas as pd
import numpy as np
from mlxtend.frequent_patterns import apriori, association_rules
from mlxtend.preprocessing import TransactionEncoder

# perform association rules based on support and confidence
def apriori_association_rules(min_support, min_confidence):
    df = pd.read_csv("attacksdataset.csv", names = ['products'], sep = ',')
    data = list(df["products"].apply(lambda x:x.split(",") ))
    '''tranform a list to 0/1 true/false'''
    a = TransactionEncoder()
    a_data = a.fit(data).transform(data)
    df = pd.DataFrame(a_data,columns=a.columns_)
    df = df.replace(False,0)
    '''run apriori'''
    df = apriori(df, min_support = min_support, use_colnames = True, verbose = 1)
    '''interpretation'''
    if  df.shape[0]:
        rules = association_rules(df, metric = "confidence", min_threshold =min_confidence)
        return rules
    else:
        return None



# check the minimum confidence and support for rule pattern
def find_min_support_and_confidence(rule_to_check, rules):
    '''print the attacks'''
    for index, row in rules.iterrows():
       x = rule_to_check[0]
       y = rule_to_check[1]
       ante =list(row['antecedents'])
       consq =list(row['consequents'])

       check_1 = all(item in x for item in ante)
       check_2 = all(item in y for item in consq)

       if check_1 & check_2 :
           return True

    return False

#Main function to perform mining
def mining_parameters(rule_to_check,min_support_threshold,min_confidence_threshold):

    rules = apriori_association_rules(min_support_threshold, min_confidence_threshold)
    '''print the attacks'''
    if rules is not None:
        check = find_min_support_and_confidence(rule_to_check, rules)
        if check is True:
            print("The rule exists")
            with open("ressources.txt", "a") as f:
                str1 = ', '.join(str(e) for e in rule_to_check[0])
                str2 = ', '.join(str(e) for e in rule_to_check[1])
                txt=  '\"'+str1+ ", "+str2+ ", "+ str(min_support_threshold)+ ", "+  str(min_confidence_threshold)+'\"\n'
                f.write(txt)

# Example usage with sample data
rule_to_check = (['192.168.0.1', '192.168.0.3', 'SQL_REQUEST'], ['SQL_TAMPERED'])
#min_support_threshold = 0.4
#min_confidence_threshold = 0.6

for s in range(1, 99, 1):
   for c in range(1, 99, 1):
       print(s*0.01, " - ",c*0.01)
       min_support_threshold =  s*0.01
       min_confidence_threshold =  c*0.01
       mining_parameters(rule_to_check,min_support_threshold,min_confidence_threshold)
