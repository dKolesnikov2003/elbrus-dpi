# -------- Makefile for DPIResultViewer (Qt 5, with folders) --------

# Compiler and Qt tools
CXX := g++
MOC := moc

# Qt flags from pkg-config
QT_CFLAGS  := $(shell pkg-config --cflags Qt5Widgets Qt5Sql)
QT_LDFLAGS := $(shell pkg-config --libs   Qt5Widgets Qt5Sql)

# Compile and link flags
CXXFLAGS := -Wall -O2 -std=c++17 -fPIC -Iinclude $(QT_CFLAGS)
LDFLAGS  := $(QT_LDFLAGS)

# Directories
SRC_DIR := src
INC_DIR := include
OBJ_DIR := obj

# Sources and headers
SRC     := $(wildcard $(SRC_DIR)/*.cpp)
HDR_MOC := $(wildcard $(INC_DIR)/*.h)
MOC_SRC := $(patsubst $(INC_DIR)/%.h,$(OBJ_DIR)/moc_%.cpp,$(HDR_MOC))

# All object files
OBJ := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRC)) \
       $(patsubst $(OBJ_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(MOC_SRC))

TARGET := el-dpi-gui

.PHONY: all clean

all: $(TARGET)

# Link final binary
$(TARGET): $(OBJ)
	$(CXX) $^ -o $@ $(LDFLAGS)

# Compile .cpp (src/) → .o
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile moc-generated .cpp → .o
$(OBJ_DIR)/%.o: $(OBJ_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Generate moc_*.cpp from headers in include/
$(OBJ_DIR)/moc_%.cpp: $(INC_DIR)/%.h
	@mkdir -p $(OBJ_DIR)
	$(MOC) $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(TARGET)
