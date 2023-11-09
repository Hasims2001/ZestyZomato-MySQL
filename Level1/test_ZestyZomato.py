import unittest
from ZestyZomato import app
import json

class ZomatoTest(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    # def test_welcome(self):
    #     response = self.app.get('/')
    #     data = json.loads(response.data)
    #     self.assertEqual(data['message'], 'Welcome to Zesty Zomato')
    
    # def test_register(self):
    #     # new user
    #     new_user= {'name': "Zoya", 'password': 'Zoya', 'role': 'user'}
    #     res = self.app.post('/register', json=new_user)
    #     data = json.loads(res.data)
    #     self.assertEqual(data['message'], 'register success')

    #     # edge case
    #     new_user= {'name': "Zoya", 'password': 'Zoya', 'role': 'user'}
    #     res = self.app.post('/register', json=new_user)
    #     data = json.loads(res.data)
    #     self.assertEqual(data['message'], 'name is already present in database')
    
    # def test_login(self):
    #     # login with same user
    #     user= {'name': "Zoya", 'password': 'Zoya', 'role': 'user'}
    #     res = self.app.post('/login', json=user)
    #     data = json.loads(res.data)
    #     self.assertEqual(data['message'], 'login success')

    #     # user with new data (edge case)
    #     user= {'name': "qwerty", 'password': 'qwerty', 'role': 'user'}
    #     res = self.app.post('/login', json=user)
    #     data = json.loads(res.data)
    #     self.assertEqual(data['message'], 'Invalid user data')


    # def test_dishes(self):
    #     # newDish with correct data
    #     newDish = {"name": "tomato chat", "price": 350, "availability": "Yes", "store":"Ahemdabad, Gujarat"}
    #     headers = { "Authorization" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJtYW5hZ2VyIHZpY2t5Iiwicm9sZSI6ImFkbWluIn19.4BXq9CUyzu1xmzbMXiXCQRgYR2mJgQ__AKSqKyE70aA"}
    #     response = self.app.post("/menu", json=newDish, headers=headers)
    #     data = json.loads(response.data)
    #     self.assertEqual(data['message'], 'dish added')

    #     # newDish with wrong token (edge case)
    #     newDish = {"name": "tomato chat", "price": 350, "availability": "Yes", "store":"Ahemdabad, Gujarat"}
    #     headers = { "Authorization" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJtYW5hZ2VyIHZpY2t5Iiwicm9sZSI6ImFkbWluIn19.4BXq9CUyzu1xmzbMXiXCQRgYR2mJgQ__AKSqK"}
    #     response = self.app.post("/menu", json=newDish, headers=headers)
    #     data = json.loads(response.data)
    #     self.assertEqual(data['message'], 'Invalid token')

    
    # def test_getDishes(self):
    #     #  getting all dishes
    #     response = self.app.get('/menu')
    #     data = json.loads(response.data)
    #     self.assertEqual(data['message'], 'Menu') 

    
    # def test_patchdish(self):
    #     # updating dish
    #     updateDish  = {"price": 200, "availability": "Yes", "store":"Ahemdabad, Gujarat"}
    #     headers = { "Authorization" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJtYW5hZ2VyIHZpY2t5Iiwicm9sZSI6ImFkbWluIn19.4BXq9CUyzu1xmzbMXiXCQRgYR2mJgQ__AKSqKyE70aA"}
    #     response = self.app.patch("/dish/11", json=updateDish, headers=headers)
    #     data = json.loads(response.data)
    #     self.assertEqual(data['message'], 'Dish with ID 11 has been updated')

    # def test_getdish(self):
    #     # getting same dish 
    #     res = self.app.get('/dish/11')
    #     data = json.loads(res.data)
    #     self.assertEqual(data['message'], "Single Dish")

    #     # checking invalid dish ID (edge case)
    #     res = self.app.get('/dish/0')
    #     data = json.loads(res.data)
    #     self.assertEqual(data['message'], "Dish not found")


    # def test_deletedish(self):
    #     # deleting same dish
    #     headers = { "Authorization" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJtYW5hZ2VyIHZpY2t5Iiwicm9sZSI6ImFkbWluIn19.4BXq9CUyzu1xmzbMXiXCQRgYR2mJgQ__AKSqKyE70aA"}
    #     res = self.app.delete('/dish/11', headers=headers)
    #     data  = json.loads(res.data)
    #     self.assertEqual(data['message'], 'Dish with ID 11 has been deleted')


    # def test_postorder(self):
    #   # new order 
    #     new_order ={
    #     "name": "alx",
    #     "email": "alx@gmail.com",
    #     "items": [
    #         {
    #     "name": "Dosa",
    #     "price": 120
    #     },{
    #     "name": "Pancakes",
    #     "price": 90
    #     }],
    #     "promocode": "",
    #     "store": "Surat, Gujarat"
    # }
                
    #     res = self.app.post('/order', json=new_order)
    #     data = json.loads(res.data)
    #     self.assertEqual(data['message'], 'order added')
    #     self.assertEqual(data['order']['status'], 'received')

    # def test_patchorder(self):
    #     # updating the status of order
    #     headers = { "Authorization" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJtYW5hZ2VyIHZpY2t5Iiwicm9sZSI6ImFkbWluIn19.4BXq9CUyzu1xmzbMXiXCQRgYR2mJgQ__AKSqKyE70aA"}

    #     res = self.app.patch('/order/5', json={'status': "preparing"}, headers=headers)
    #     data = json.loads(res.data)
    #     self.assertEqual(data['message'], f"Order with ID 5 has been updated")
        
    # def test_getorder(self):

    #     res = self.app.get('/order/5')
    #     data = json.loads(res.data)
    #     self.assertEqual(data['message'], 'Single Order')
    #     self.assertEqual(data['order']['status'], "preparing")

    #     # getting invalid order (edge case)
    #     res = self.app.get('/order/0')
    #     data = json.loads(res.data)
    #     self.assertEqual(data['message'], 'Order not found')
        
    # def test_deleteorder(self):
    #     headers = { "Authorization" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJtYW5hZ2VyIHZpY2t5Iiwicm9sZSI6ImFkbWluIn19.4BXq9CUyzu1xmzbMXiXCQRgYR2mJgQ__AKSqKyE70aA"}
    #     res = self.app.delete('/order/3', headers=headers)
    #     data = json.loads(res.data)
    #     self.assertEqual(data['message'], "Order with ID 3 has been deleted")


    # def test_order_filter(self):
    #     headers = { "Authorization" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJtYW5hZ2VyIHZpY2t5Iiwicm9sZSI6ImFkbWluIn19.4BXq9CUyzu1xmzbMXiXCQRgYR2mJgQ__AKSqKyE70aA"}
    #     res = self.app.get("/order/filter/received", headers=headers)
    #     data = json.loads(res.data)
    #     self.assertEqual(data['message'], "filtered orders where status is received")

    #     # checking invalid filteration (edge case)
    #     res = self.app.get('/order/filter/Invalid', headers=headers)
    #     data = json.loads(res.data)
    #     self.assertEqual(data['message'], "Order not found")
    
        

if __name__ == '__main__':
    unittest.main()
