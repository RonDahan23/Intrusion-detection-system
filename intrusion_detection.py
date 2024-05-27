import tensorflow as tf
import numpy as np
from sklearn.metrics import classification_report, ConfusionMatrixDisplay

class IntrusionDetectionModel:
    def __init__(self, model_path, x_test_path, y_test_path):
        self.model = tf.keras.models.load_model(model_path)
        self.X_Test = np.load(x_test_path)
        self.y_Test = np.load(y_test_path)
        self.class_names = ["normal", "anomaly"]

    def evaluate_model(self):
        preds = self.model.predict(self.X_Test)
        y_pred = tf.where(preds < 0.5, 0, 1).numpy()
        print(classification_report(self.y_Test, y_pred, digits=4))

    def classify(self, X1):
        X1 = np.expand_dims(X1, axis=0)
        preds = self.model.predict(X1)
        y_pred = tf.where(preds < 0.5, 0, 1).numpy()
        return self.class_names[y_pred[0][0]]

