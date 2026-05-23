from list import ListModel, TargetedListModel
from markov import MarkovModel, TargetedMarkovModel
from pcfg import PCFGModel
import pickle
import itertools
from util import *


def main() -> None:
    
    # query = UserData("big_chungusBBBBBBBBBBBBBBB", "chAngAs22@gmail.com", "chEngEs11", "Big", "Chungus", "03052002")
    # model = TargetedListModel()
 
    # data = [
    #     ["johnnnAA456Porkson1997BB?C", "johnn456@gmail.com", "porksonn999", "john", "porkson", "11121997"],
    # ]
    
    query = UserData("big_chungusBBBBBBBBBBBBBBB", "chAngAs22@gmail.com", "chEngEs11", "Big", "Chungus", "03052002")
    # model = MarkovModel("./Christos/trained_models/markov.pickle")
    model = PCFGModel()
    
    with open("C:/Users/ctamv/Documents/CS/CS4710/BreachCompilation/preprocessed_data/train_data.pickle", 'rb') as f:
        data = pickle.load(f)
    data = list(itertools.chain.from_iterable(data))
    data = [[x] for x in data][:1000]
    
    # query = UserData("big_chungusBBBBBBBBBBBBBBB", "chAngAs22@gmail.com", "chEngEs11", "Big", "Chungus", "03052002")
    # model = TargetedMarkovModel()
    
    # data = [
    #     ["johnnnAAAA456Porkson1997?C", "johnn456@gmail.com", "porksonn999", "john", "porkson", "11121997"],
    #     ["22chungaAAAA2000!chun", "chunchun22@gmail.com", "chungas", "chunga", "Chungsten", "11122000"]
    # ]

    model.load_data(data)
    res = model.generate(10)
    
    aa = 0


if __name__ == "__main__":
    main()