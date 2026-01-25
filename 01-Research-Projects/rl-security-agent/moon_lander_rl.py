import gymnasium as gym
from stable_baselines3 import PPO
import os

# ১. এনভায়রনমেন্ট বানাচ্ছি (খেলার মাঠ)
# render_mode="human" দিলে তুই চোখে দেখবি এজেন্ট কী করতেছে।
# কিন্তু ট্রেইনিংয়ের সময় এটা দিবি না, কারণ এতে স্লো হয়ে যায়।
env = gym.make("LunarLander-v2", render_mode="human")

# ২. মডেল বানাচ্ছি (এজেন্টের মস্তিষ্ক)
# PPO অ্যালগরিদম নিচ্ছি। MlpPolicy মানে সাধারণ নিউরাল নেটওয়ার্ক।
model = PPO("MlpPolicy", env, verbose=1)

print("Training")

model.learn(total_timesteps=10000)

print("Finished Training")

