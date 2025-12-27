import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM, Dropout, BatchNormalization

def build_lstm_model(input_shape):
    """
    Builds the Deep Learning Model (LSTM) for GuardNet.
    Structure:
    - LSTM Layer: Captures temporal patterns in packet flows.
    - Dropout: Prevents overfitting.
    - Dense Layers: Classification.
    """
    model = Sequential()

    # Layer 1: LSTM (The memory layer)
    # input_shape should be (time_steps, features)
    model.add(LSTM(64, input_shape=input_shape, return_sequences=True))
    model.add(Dropout(0.2))

    # Layer 2: LSTM (Deep feature extraction)
    model.add(LSTM(32, return_sequences=False))
    model.add(Dropout(0.2))

    # Layer 3: Fully Connected
    model.add(Dense(32, activation='relu'))
    model.add(BatchNormalization())

    # Output Layer: Binary Classification (0=Normal, 1=Attack)
    # Note: Use 'softmax' and more units if doing multi-class classification
    model.add(Dense(1, activation='sigmoid'))

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    
    return model