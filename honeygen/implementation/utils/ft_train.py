import fasttext


def train_model():
   """
   This function is used to train the FastText model for creating the passowrds' embeddings.
   :return: Exports the trained .bin model.
   """
   dataset = "youku"
   # "dropbox" | "linkedin" | "yahoo" | "chegg-com" | "dubsmash-com" | "youku"
   #first train 1 of the two models: spipgram or cbow

   # Skipgram model:
   epochs= 500
   model = fasttext.train_unsupervised(f'../data/50k_subsample/{dataset}_sorted_preprocessed.txt', minCount=1, minn=2, epoch=epochs, model='skipgram')

   print()

   #save model
   model.save_model(f"model_trained_on_{dataset}_"+str(epochs)+"_epochs.bin")
   print("Model saved")



#execute program
train_model()