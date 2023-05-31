# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

add_executable(client client.c)
add_executable(client_clock client.c)
add_executable(client_wall client.c)

target_compile_definitions(client_clock PUBLIC MEASURE_CLOCK_TIME)
target_compile_definitions(client_wall PUBLIC MEASURE_WALL_TIME)
