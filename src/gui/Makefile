# -------- Makefile for DPIResultViewer (Qt 5) --------

# Compiler and Qt tools
CXX       := g++
MOC       := moc           # On Debian Qt tools are named moc-qt5 / uic-qt5 etc.

# Use pkg-config to fetch Qt compile & link flags
QT_CFLAGS  := $(shell pkg-config --cflags Qt5Widgets Qt5Sql)
QT_LDFLAGS := $(shell pkg-config --libs   Qt5Widgets Qt5Sql)

CXXFLAGS := -Wall -O2 -std=c++17 -fPIC $(QT_CFLAGS)
LDFLAGS  := $(QT_LDFLAGS)

# Directories
OBJ_DIR := obj
BIN_DIR := bin

# Sources & headers
SRC     := main.cpp mainwindow.cpp timedelegate.cpp
HDR_MOC := mainwindow.h timedelegate.h
MOC_SRC := $(HDR_MOC:%.h=moc_%.cpp)

# Object files go in $(OBJ_DIR), binary in $(BIN_DIR)
OBJ    := $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(SRC) $(MOC_SRC))
TARGET := $(BIN_DIR)/el-dpi-gui

# Default target
all: $(TARGET)

# Link executable (ensure bin/ exists)
$(TARGET): $(OBJ)
	@mkdir -p $(BIN_DIR)
	$(CXX) $^ -o $@ $(LDFLAGS)

# Compile C++ sources into obj/*.o
$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Generate moc_*.cpp from headers
moc_%.cpp: %.h
	$(MOC) $< -o $@

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	rm -f $(MOC_SRC)

.PHONY: all clean
