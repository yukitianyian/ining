import requests

#字典方式拼接参数
data={
    "data": "Xsw9nDdD3K7mBN0wTM6ENwayHDfTFbybly3Ufjr1RS1SdjvkOV9hSaqAxCOV1RfbZouRg3CRElV3WBMGbwIMZLHn35E5hR0GFnp8tsdnMkmB4kZdvWzq71T245XIwv6dgK/cIQ5USbUI9ZY9v1SNu8YqfB1gZTksVzvFD0mVivfUyfqHAViyhsc25qK4qZTzxV9/dq0Xi0sE6oI6WSw6O9xzs6iCUM1+s1Z9vpDqhZU6o5EYSkb95f+wMzG7F0tJVE6tHcIS1LmImeONf48Vckx23cptpxsPg/SGKB7Enjw+keBDuepRBZdtSTQsNOXWUyAJlj53DJmUukgS4/YFUg==",
    "sign": "pvZBup3MzyTGM5ejzJmEZS28k9i7TRs1mrLglUQAz0RCSwycbfj5tRj3s2fYIo8+GwRds7o8czqNKm5MkZZ81aAjdnjIF5IvQLpUqDw4PPrz8n/YN6CqcMOWJzc89qz4msbVLws+BNy4U9MErBJPd2c3sur802H2qLC/azYCpKBeexI4a3SlVDalfb7curwc6zw6F7qQxLDrok7Sn/qimeNe7hYblT3bbdcbrqkVgQcpWT66I3vTyfn63SFkT6VDOcu6h/Isc48uHeSJT1yf//DDhSUtr0G3xT/HzvmnKbTQZ0RSm9pB6YWei6MMwvUoKuPxmwEaTe6xTMM/Yy5hPQ=="

}

response1 = requests.post(url="http://127.0.0.1:5005/payroute/app/getSignOrders", data = data)
print(response1.text)
print(response1.json())

#获取响应状态码
print(response1.status_code)

#获取原始模式
print(response1.raw)
