# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/qwebify/rendu/secu/2016_P3p1t0/pepito

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/qwebify/rendu/secu/2016_P3p1t0/pepito

# Include any dependencies generated for this target.
include CMakeFiles/pepito.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/pepito.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/pepito.dir/flags.make

CMakeFiles/pepito.dir/src/daemon.o: CMakeFiles/pepito.dir/flags.make
CMakeFiles/pepito.dir/src/daemon.o: src/daemon.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/pepito.dir/src/daemon.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pepito.dir/src/daemon.o   -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/daemon.c

CMakeFiles/pepito.dir/src/daemon.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pepito.dir/src/daemon.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/daemon.c > CMakeFiles/pepito.dir/src/daemon.i

CMakeFiles/pepito.dir/src/daemon.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pepito.dir/src/daemon.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/daemon.c -o CMakeFiles/pepito.dir/src/daemon.s

CMakeFiles/pepito.dir/src/daemon.o.requires:

.PHONY : CMakeFiles/pepito.dir/src/daemon.o.requires

CMakeFiles/pepito.dir/src/daemon.o.provides: CMakeFiles/pepito.dir/src/daemon.o.requires
	$(MAKE) -f CMakeFiles/pepito.dir/build.make CMakeFiles/pepito.dir/src/daemon.o.provides.build
.PHONY : CMakeFiles/pepito.dir/src/daemon.o.provides

CMakeFiles/pepito.dir/src/daemon.o.provides.build: CMakeFiles/pepito.dir/src/daemon.o


CMakeFiles/pepito.dir/src/main.o: CMakeFiles/pepito.dir/flags.make
CMakeFiles/pepito.dir/src/main.o: src/main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/pepito.dir/src/main.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pepito.dir/src/main.o   -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/main.c

CMakeFiles/pepito.dir/src/main.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pepito.dir/src/main.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/main.c > CMakeFiles/pepito.dir/src/main.i

CMakeFiles/pepito.dir/src/main.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pepito.dir/src/main.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/main.c -o CMakeFiles/pepito.dir/src/main.s

CMakeFiles/pepito.dir/src/main.o.requires:

.PHONY : CMakeFiles/pepito.dir/src/main.o.requires

CMakeFiles/pepito.dir/src/main.o.provides: CMakeFiles/pepito.dir/src/main.o.requires
	$(MAKE) -f CMakeFiles/pepito.dir/build.make CMakeFiles/pepito.dir/src/main.o.provides.build
.PHONY : CMakeFiles/pepito.dir/src/main.o.provides

CMakeFiles/pepito.dir/src/main.o.provides.build: CMakeFiles/pepito.dir/src/main.o


CMakeFiles/pepito.dir/src/network.o: CMakeFiles/pepito.dir/flags.make
CMakeFiles/pepito.dir/src/network.o: src/network.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/pepito.dir/src/network.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pepito.dir/src/network.o   -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/network.c

CMakeFiles/pepito.dir/src/network.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pepito.dir/src/network.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/network.c > CMakeFiles/pepito.dir/src/network.i

CMakeFiles/pepito.dir/src/network.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pepito.dir/src/network.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/network.c -o CMakeFiles/pepito.dir/src/network.s

CMakeFiles/pepito.dir/src/network.o.requires:

.PHONY : CMakeFiles/pepito.dir/src/network.o.requires

CMakeFiles/pepito.dir/src/network.o.provides: CMakeFiles/pepito.dir/src/network.o.requires
	$(MAKE) -f CMakeFiles/pepito.dir/build.make CMakeFiles/pepito.dir/src/network.o.provides.build
.PHONY : CMakeFiles/pepito.dir/src/network.o.provides

CMakeFiles/pepito.dir/src/network.o.provides.build: CMakeFiles/pepito.dir/src/network.o


CMakeFiles/pepito.dir/src/utils.o: CMakeFiles/pepito.dir/flags.make
CMakeFiles/pepito.dir/src/utils.o: src/utils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/pepito.dir/src/utils.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pepito.dir/src/utils.o   -c /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/utils.c

CMakeFiles/pepito.dir/src/utils.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pepito.dir/src/utils.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/utils.c > CMakeFiles/pepito.dir/src/utils.i

CMakeFiles/pepito.dir/src/utils.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pepito.dir/src/utils.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/qwebify/rendu/secu/2016_P3p1t0/pepito/src/utils.c -o CMakeFiles/pepito.dir/src/utils.s

CMakeFiles/pepito.dir/src/utils.o.requires:

.PHONY : CMakeFiles/pepito.dir/src/utils.o.requires

CMakeFiles/pepito.dir/src/utils.o.provides: CMakeFiles/pepito.dir/src/utils.o.requires
	$(MAKE) -f CMakeFiles/pepito.dir/build.make CMakeFiles/pepito.dir/src/utils.o.provides.build
.PHONY : CMakeFiles/pepito.dir/src/utils.o.provides

CMakeFiles/pepito.dir/src/utils.o.provides.build: CMakeFiles/pepito.dir/src/utils.o


# Object files for target pepito
pepito_OBJECTS = \
"CMakeFiles/pepito.dir/src/daemon.o" \
"CMakeFiles/pepito.dir/src/main.o" \
"CMakeFiles/pepito.dir/src/network.o" \
"CMakeFiles/pepito.dir/src/utils.o"

# External object files for target pepito
pepito_EXTERNAL_OBJECTS =

pepito: CMakeFiles/pepito.dir/src/daemon.o
pepito: CMakeFiles/pepito.dir/src/main.o
pepito: CMakeFiles/pepito.dir/src/network.o
pepito: CMakeFiles/pepito.dir/src/utils.o
pepito: CMakeFiles/pepito.dir/build.make
pepito: lib/libsecret.so
pepito: lib/libsupersecret.so
pepito: CMakeFiles/pepito.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C executable pepito"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/pepito.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/pepito.dir/build: pepito

.PHONY : CMakeFiles/pepito.dir/build

CMakeFiles/pepito.dir/requires: CMakeFiles/pepito.dir/src/daemon.o.requires
CMakeFiles/pepito.dir/requires: CMakeFiles/pepito.dir/src/main.o.requires
CMakeFiles/pepito.dir/requires: CMakeFiles/pepito.dir/src/network.o.requires
CMakeFiles/pepito.dir/requires: CMakeFiles/pepito.dir/src/utils.o.requires

.PHONY : CMakeFiles/pepito.dir/requires

CMakeFiles/pepito.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/pepito.dir/cmake_clean.cmake
.PHONY : CMakeFiles/pepito.dir/clean

CMakeFiles/pepito.dir/depend:
	cd /home/qwebify/rendu/secu/2016_P3p1t0/pepito && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/qwebify/rendu/secu/2016_P3p1t0/pepito /home/qwebify/rendu/secu/2016_P3p1t0/pepito /home/qwebify/rendu/secu/2016_P3p1t0/pepito /home/qwebify/rendu/secu/2016_P3p1t0/pepito /home/qwebify/rendu/secu/2016_P3p1t0/pepito/CMakeFiles/pepito.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/pepito.dir/depend
