import numpy as np
import cv2
import os
import tensorflow as tf
from keras_preprocessing.image import ImageDataGenerator

train_data_gen = ImageDataGenerator(rescale = 1./255,
                                    zca_epsilon=1e-06,
                                    rotation_range=90,
                                    width_shift_range=0.1,
                                    height_shift_range=0.1,
                                    fill_mode='nearest',
                                    shear_range = 0.2,
                                    zoom_range = 0.2,
                                    horizontal_flip = True,
                                    vertical_flip = True)
training_set = train_data_gen.flow_from_directory('train',
                                                  target_size = (64, 64),
                                                  batch_size = 12,
                                                  class_mode = 'categorical')

validation_data_gen = ImageDataGenerator(rescale = 1./255)
validation_set = validation_data_gen.flow_from_directory('valid',
                                                          target_size = (64, 64),
                                                          batch_size = 12,
                                                          class_mode = 'categorical')

from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense, Activation

Model = Sequential()
shape = (64, 64, 3)
Model.add(Conv2D(32,(3,3), activation='relu', input_shape=shape))
Model.add(MaxPooling2D(2,2))
Model.add(Conv2D(32,(3,3), activation='relu'))
Model.add(MaxPooling2D(2,2))
Model.add(Conv2D(64,(3,3), activation='relu'))
Model.add(MaxPooling2D(2,2))
Model.add(Flatten())
Model.add(Dense(512, activation='relu'))
Model.add(Dense(5, activation='softmax'))
Model.summary()
optimizer = tf.keras.optimizers.Adam(learning_rate=0.001)
Model.compile(optimizer = optimizer, loss = 'categorical_crossentropy', metrics = ['accuracy'])

print("Bắt đầu huấn luyện...")
history = Model.fit_generator(training_set,
                    steps_per_epoch = 50,
                    epochs = 20,
                    validation_data = validation_set,
                    validation_steps = 20)
Model.save("model.keras")
