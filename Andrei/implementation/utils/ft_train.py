import fasttext


def train_model():
   """
   This function is used to train the FastText model for creating the passowrds' embeddings.
   :return: Exports the trained .bin model.
   """

   #first train 1 of the two models: spipgram or cbow

   # Skipgram model:
   epochs= 500
   model = fasttext.train_unsupervised('data/50k_subsample/rockyou_sorted_preprocessed.txt', minCount=1, minn=2, epoch=epochs, model='skipgram')

   print()

   #save model
   model.save_model("model_trained_on_rockyou_"+str(epochs)+"_epochs.bin")
   print("Model saved as model_trained_on_rockyou_"+str(epochs)+"_epochs.bin")



#execute program
train_model()