import numpy as np
import cv2
import os
import tensorflow as tf
from PIL import Image
from tensorflow.keras.models import load_model

label = ['Cà chua','Cà rốt','Dưa chuột','Khoai tây', 'Ớt chuông']

model = load_model("model.keras")

def predict_images_in_folder(folder_path, folder_name, num_images):
    file_names = os.listdir(folder_path)

    for i, file_name in enumerate(file_names[:num_images]):
        file_path = os.path.join(folder_path, file_name)

        image = cv2.imread(file_path)
        image = cv2.resize(image, (64, 64))
        image_pil = Image.fromarray(image)
        image_np = np.array(image_pil)
        image_np = np.expand_dims(image_np, axis=0)
        result = model.predict(image_np)
        final = np.argmax(result)
        predicted_label = label[final]

        print('Kết quả dự đoán cho ảnh {}: {}'.format(i+1, predicted_label))
        cv2.imshow('Image {}'.format(i+1), image)
        cv2.waitKey(0)
        cv2.destroyAllWindows()

    print("Hoàn tất dự đoán.")

def main():
    while True:
        folder_path = "test\\" 
        folder_name = input("Nhập tên thư mục: ")
        folder_path += folder_name

        if not os.path.exists(folder_path):
            print("Thư mục không tồn tại.")
            break

        while True:
            num_images = input("Nhập số lượng ảnh muốn dự đoán: ")
            try:
                num_images = int(num_images)
                break
            except ValueError:
                print("Vui lòng nhập một số nguyên.")

        predict_images_in_folder(folder_path, folder_name, num_images)

if __name__ == "__main__":
    main()
