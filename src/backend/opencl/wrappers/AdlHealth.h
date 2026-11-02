/* XMRig
 * Copyright 2008-2018 Advanced Micro Devices, Inc.
 * Copyright 2018-2020 SChernykh                    <https://github.com/SChernykh>
 * Copyright 2016-2020 XMRig                        <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef XMRIG_ADLHEALTH_H
#define XMRIG_ADLHEALTH_H


#include <cstdint>
#include <vector>
#include <string>


struct AdlHealth
{
    int edge = -1;
    int hotspot = -1;
    int memory = -1;
    uint64_t polled = 0;
    const char *source = "unavailable";
    bool powerValid = false;
    const char *powerScope = "unavailable";
    const char *powerSource = "unavailable";
    bool rpmValid = false;
    // ADL PMLog reports watts. Board power includes the card, ASIC power does not.
    void setPower(bool boardSupported, int boardWatts, bool asicSupported, int asicWatts)
    {
        powerValid = false;
        power = 0;
        powerScope = powerSource = "unavailable";
        if (boardSupported && boardWatts >= 0 && boardWatts <= 2000) {
            power = static_cast<uint32_t>(boardWatts);
            powerValid = true;
            powerScope = "board";
            powerSource = "adl-pmlog-board";
        }
        else if (asicSupported && asicWatts >= 0 && asicWatts <= 2000) {
            power = static_cast<uint32_t>(asicWatts);
            powerValid = true;
            powerScope = "asic";
            powerSource = "adl-pmlog-asic";
        }
    }
    static std::string number(int value) { return value < 0 ? "null" : std::to_string(value); }
    std::string json(uint32_t gpu, const char *pci) const
    {
        return "{\"v\":1,\"gpu\":" + std::to_string(gpu) + ",\"pci\":\"" + pci +
            "\",\"source\":\"" + source + "\",\"polled_ms\":" + std::to_string(polled) +
            ",\"edge_c\":" + number(edge) + ",\"hotspot_c\":" + number(hotspot) +
            ",\"memory_c\":" + number(memory) + ",\"power_w\":" + (powerValid ? std::to_string(power) : "null") +
            ",\"power_scope\":\"" + powerScope + "\",\"power_source\":\"" + powerSource + "\"" +
            ",\"fan_rpm\":" + (rpmValid ? std::to_string(rpm) : "null") + "}";
    }
    uint32_t clock          = 0;
    uint32_t memClock       = 0;
    uint32_t power          = 0;
    uint32_t rpm            = 0;
    uint32_t temperature    = 0;
};


#endif /* XMRIG_ADLHEALTH_H */
