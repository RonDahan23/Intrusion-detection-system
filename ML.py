import tensorflow as tf
import numpy as np
from sklearn.metrics import classification_report, ConfusionMatrixDisplay

model = tf.keras.models.load_model("/home/ron/ids_projetc/model")
X_Test = np.load("/home/ron/ids_projetc/model/np_X_Test.npy")
y_Test = np.load("/home/ron/ids_projetc/model/np_y_Test.npy")

preds = model.predict(X_Test)
y_pred = tf.where(preds < 0.5, 0, 1).numpy()

print(classification_report(y_Test, y_pred, digits=4))

class_names = ["normal", "anomaly"]

def classify(X1):
    X1 = np.expand_dims(X1, axis=0)
    preds = model.predict(X1)
    y_pred = tf.where(preds < 0.5, 0, 1).numpy()
    return class_names[y_pred[0][0]]

X1 = np.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 6, 1, 1, 0, 0, 0.05, 0.07, 0, 255, 26, 0.1, 0.05, 0, 0, 1, 1, 0, 0])
X1 = X_Test[0]
print(X1.shape)

print(classify(X1))
