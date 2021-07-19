# -*- coding:utf-8 -*
# # -*- coding:utf-8 -*-
# from celery import Celery
# import time
# broker='redis://127.0.0.1:5000'
# backend='redis://127.0.01:5000/0'
# app=Celery('tasks',broker=broker,backend=backend)
#
# @app.task
# def add():
#     # time.sleep(5)
#     return "任务正在执行..."

from celery import Celery

# 我们这里案例使用redis作为broker
app = Celery('demo', broker='redis://:332572@127.0.0.1/1')


# 创建任务函数
@app.task
def my_task():
    print("任务函数正在执行....")
