import gymnasium as gym
from stable_baselines3 import PPO
import os

env = gym.make("CartPole-v1", render_mode="human")

print("মামা, ট্রেনিং শুরু হচ্ছে... একটু ওয়েট কর!")
model = PPO("MlpPolicy", env, verbose=1)

model.learn(total_timesteps=10000)

print("ট্রেনিং শেষ মামা! এখন দেখ ওস্তাদের কারিশমা...")

vec_env = model.get_env()
obs = vec_env.reset()

for i in range(1000):
    action, _states = model.predict(obs, deterministic=True)
    obs, rewards, dones, info = vec_env.step(action)
    
    if dones:
        print(f"ধুর বাল! {i} স্টেপে পড়ে গেল!")
        obs = vec_env.reset()

env.close()
print("খেলা শেষ!")