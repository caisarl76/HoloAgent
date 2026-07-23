/*
LICENSE

This project as a whole is licensed under the Apache License, Version 2.0.

THIRD-PARTY LICENSES

Third-party software already included in HoloAgent is governed by the separate 
Open Source license terms under which the third-party software has been distributed.

NOTICE ON LICENSE COMPATIBILITY FOR DISTRIBUTORS

Notably, this project depends on the third-party software FAST-LIVO2 and HOVSG. 
Their default licenses restrict commercial use—separate permission from their 
original authors is required for commercial integration/redistribution.

The third-party software FAST-LIVO2 dependency (licensed under GPL-2.0-only) 
utilizes rpg_vikit-ros2 which contains components under the GPL-3.0. Please be 
aware of license compatibility when distributing a combined work.

DISCLAIMER

Users are solely responsible for ensuring compliance with all applicable license 
terms when using, modifying, or distributing the project. Project maintainers 
accept no liability for any license violations arising from such use.
*/
#include <unitree/robot/g1/loco/g1_loco_api.hpp>
#include <unitree/robot/g1/loco/g1_loco_client.hpp>
#include <algorithm>
#include <cmath>
#include <cctype>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <fstream>
#include <memory>
#include <string>
#include <unistd.h>

struct Vel
{
  float x;
  float y;
  float r;
  Vel() : x(0.0f), y(0.0f), r(0.0f) {}
  Vel(float a, float b, float c) : x(a), y(b), r(c) {}
};

float getenv_float(const char *name, float default_value)
{
  const char *raw = std::getenv(name);
  if (raw == nullptr || raw[0] == '\0') {
    return default_value;
  }
  try {
    return std::stof(raw);
  } catch (const std::exception &) {
    std::cerr << "Invalid " << name << "=" << raw
              << ", using " << default_value << std::endl;
    return default_value;
  }
}

bool getenv_bool(const char *name, bool default_value)
{
  const char *raw = std::getenv(name);
  if (raw == nullptr || raw[0] == '\0') {
    return default_value;
  }
  std::string value(raw);
  std::transform(value.begin(), value.end(), value.begin(), ::tolower);
  if (value == "1" || value == "true" || value == "yes" || value == "on") {
    return true;
  }
  if (value == "0" || value == "false" || value == "no" || value == "off") {
    return false;
  }
  std::cerr << "Invalid " << name << "=" << raw
            << ", using " << (default_value ? "true" : "false") << std::endl;
  return default_value;
}

float clamp_abs(float value, float limit)
{
  const float abs_limit = std::max(0.0f, std::abs(limit));
  return std::clamp(value, -abs_limit, abs_limit);
}

int main(int argc, char * argv[])
{

  const char * iface_env = std::getenv("UNITREE_NET_IFACE");
  std::string iface = (iface_env && iface_env[0] != '\0') ? iface_env : "eth0";
  const bool dry_run = getenv_bool("G1_DRY_RUN", true);
  const float max_linear_x = getenv_float("G1_MAX_LINEAR_X", 0.22f);
  const float max_linear_y = getenv_float("G1_MAX_LINEAR_Y", 0.0f);
  const float max_yaw = getenv_float("G1_MAX_YAW_RATE", 0.30f);
  const float min_yaw_when_rotating = getenv_float("G1_MIN_ROTATING_YAW_RATE", 0.30f);
  const float min_yaw_when_moving = getenv_float("G1_MIN_MOVING_YAW_RATE", 0.10f);

  std::cout << "Using Unitree network interface: " << iface << std::endl;
  std::cout << "G1_DRY_RUN=" << (dry_run ? "1" : "0")
            << " G1_MAX_LINEAR_X=" << max_linear_x
            << " G1_MAX_LINEAR_Y=" << max_linear_y
            << " G1_MAX_YAW_RATE=" << max_yaw << std::endl;

  std::unique_ptr<unitree::robot::g1::LocoClient> client;
  if (!dry_run) {
    unitree::robot::ChannelFactory::Instance()->Init(0, iface.c_str());
    client = std::make_unique<unitree::robot::g1::LocoClient>();
    client->Init();
    client->SetTimeout(10.f);
  } else {
    std::cout << "Dry-run enabled: velocity commands will be logged but not sent to G1." << std::endl;
  }

  std::ifstream velpipe("/tmp/vel_fifo", std::ios::binary);
  Vel value;
  while (true) {
      //std::cout<<"move"<<std::endl;
      //client.Move(0.2, 0.0, 0.0);
      
      velpipe.read(reinterpret_cast<char*>(&value), sizeof(Vel));
      if (velpipe.gcount() == sizeof(Vel)) {
            
            if(value.x==0.0 && value.y==0.0f)
            {
                if(value.r>0.0f && value.r<min_yaw_when_rotating)
                {
                    value.r = min_yaw_when_rotating;
                }
                else
                {
                    if(value.r<0.0f && value.r>-min_yaw_when_rotating)
                    {
                        value.r = -min_yaw_when_rotating;
                    }
                }
                
            }
            else
            {
                if(value.r<min_yaw_when_moving && value.r>0.0f)
                {
                    value.r = min_yaw_when_moving;
                }
                else
                {
                    if(value.r>-min_yaw_when_moving && value.r<0.0f)
                    {
                        value.r = -min_yaw_when_moving;
                    }
                }
                
            }

            value.x = clamp_abs(value.x, max_linear_x);
            value.y = clamp_abs(value.y, max_linear_y);
            value.r = clamp_abs(value.r, max_yaw);

            std::cout << "Command: " << value.x <<","<<value.y<<","<<value.r;
            if (dry_run) {
              std::cout << " [dry-run]" << std::endl;
            } else {
              std::cout << std::endl;
              client->Move(value.x, value.y, value.r);
            }
            //client.Damp();
      } else {
          //std::cout<<"no data"<<std::endl;
          usleep(10000);  // 短暂休眠
      }
      
  }
  
  return 0;
}
