from list import ListModel, TargetedListModel, UserData
from list import ListModel
from markov import MarkovModel


def main() -> None:
    
    query = UserData("big_chungusBBBBBBBBBBBBBBB", "chAngAs22@gmail.com", "chEngEs11", "Big", "Chungus", "03052002")
    model = TargetedListModel()
 
    data = [
        ["johnnnAA456Porkson1997BB?C", "johnn456@gmail.com", "porksonn999", "john", "porkson", "11121997"],
    ]
    model.load_data(data)
    res = model.generate(query, 1)
    
    aa = 0


if __name__ == "__main__":
    main()