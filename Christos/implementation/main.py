from list import ListModel, TargetedListModel
from markov import MarkovModel, TargetedMarkovModel
from pcfg import PCFGModel, TargetedPCFGModel
from mimesis import Person, Internet, Datetime
from mimesis.locales import Locale
import random
import csv
import pickle
import itertools
from util import *

def gen_synthetic_data():
    
    with open("C:/Users/ctamv/Documents/CS/CS4710/BreachCompilation/preprocessed_data/train_data.pickle", 'rb') as f:
        data = pickle.load(f)
    data = list(itertools.chain.from_iterable(data))
    
    total_rows = len(data)
    filename = "synthetic.csv"
    
    # Initialize the specific Mimesis data providers
    person = Person(Locale.EN)
    internet = Internet()
    datetime_provider = Datetime()
    
    header = ["password", "email", "username", "first_name", "last_name", "birthday"]
    
    print(f"Generating {total_rows:,} rows utilizing Mimesis...")
    
    with open(filename, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        
        for i in range(total_rows):
            fn = person.first_name()
            ln = person.last_name()
            
            row = [
                data[i],
                random.choice([fn, fn.lower(), fn.upper()]),
                random.choice([ln, ln.lower(), ln.upper()]),
                person.email(domains=["gmail.com", "yahoo.com", "@hotmail.com", "@outlook.com"]),
                datetime_provider.formatted_date(fmt="%d%m%Y"),
                person.username()
            ]
            
            writer.writerow(row)
            
            if (i + 1) % 10_000 == 0:
                print(f"Progress: {i + 1:,} rows written.")
                
    print(f"Finished! Saved to {filename}")

def main() -> None:
    
    # query = UserData("big_chungusBBBBBBBBBBBBBBB", "chAngAs22@gmail.com", "chEngEs11", "Big", "Chungus", "03052002")
    # model = TargetedListModel()
 
    # data = [
    #     ["johnnnAA456Porkson1997BB?C", "johnn456@gmail.com", "porksonn999", "john", "porkson", "11121997"],
    # ]
    
    query = UserData("big_chungusB", "chAngAs22@gmail.com", "chEngEs11", "Big", "Chungus", "03052002")
    # model = MarkovModel("./Christos/trained_models/markov.pickle")
    model = TargetedPCFGModel()
    
    # with open("C:/Users/ctamv/Documents/CS/CS4710/BreachCompilation/preprocessed_data/train_data.pickle", 'rb') as f:
    #     data = pickle.load(f)
    # data = list(itertools.chain.from_iterable(data))
    # data = [[x] for x in data][:1000]
    
    # data = []
    # with open("synthetic.csv", mode="r", newline="", encoding="utf-8") as file:
        
    #     reader = csv.reader(file)
    #     header = next(reader)

    #     row_count = 0
    #     for row in reader:
    #         data.append(row)
    #         row_count += 1
            
    #         if row_count % 10_000 == 0:
    #             print(f"Progress: Read {row_count:,} rows...")
    
    # query = UserData("big_chungusBBBBBBBBBBBBBBB", "chAngAs22@gmail.com", "chEngEs11", "Big", "Chungus", "03052002")
    # model = TargetedMarkovModel()
    
    # data = [
    #     ["johnnnAAAA456Porkson1997?C", "johnn456@gmail.com", "porksonn999", "john", "porkson", "11121997"],
    #     ["22chungasAAAA2000!chun", "chunchun22@gmail.com", "chungas", "chunga", "Chungsten", "11122000"]
    # ]

    model.load_data(rule_name="Targeted")
    res = model.generate(10, query)
    
    aa = 0


if __name__ == "__main__":
    main()