# Apollo Profile Manager

Apollo Profile Manager is a tool designed to manage and automatically swap game configuration files, save files, and other user data between different clients of [Apollo](https://github.com/ClassicOldSong/Apollo). It provides a graphical interface for managing profiles, tracking file paths, and handling client-specific saves, making it easy to maintain separate configurations for different users or devices.

Requires [Apollo v0.3.5-alpha.2 or above](https://github.com/ClassicOldSong/Apollo/releases), does not work with Sunshines.

> [!Note]
> Containing AI generated code, manually reviewed, modified and tested.

## Download

You can find the pre-built binary in [Releases](./releases)

## Usage

1.  Run the built binary (e.g., `manager.exe` in the `dist` folder).
2.  When prompted, select your Apollo configuration file (typically `sunshine.conf`).
3.  After the main application window appears, you can manually add files that you want the manager to track.

## Prerequisites

- Python 3.x
- pip (Python package installer)

## Setup

1.  **Clone the repository (if you haven't already):**
    ```bash
    git clone https://github.com/ClassicOldSong/ApolloProfileManager
    cd ApolloProfileManager
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    ```
    Activate the virtual environment:
    - Windows:
      ```bash
      .\venv\Scripts\activate
      ```
    - macOS/Linux:
      ```bash
      source venv/bin/activate
      ```

3.  **Install dependencies:**
    Make sure you have a `requirements.txt` file with all necessary packages (including PyInstaller).
    ```bash
    pip install -r requirements.txt
    ```

## Building the Executable

To build a single executable file from the Python script, you can use PyInstaller (which should be installed via `requirements.txt`).

1.  **Build the executable:**
    Navigate to the project's root directory (where `manager.py` is located) in your terminal or command prompt. Then run the following command:
    ```bash
    pyinstaller [--onefile] --noconsole manager.py
    ```
    -   `--onefile`: Creates a single executable file, but starts slower.
    -   `--noconsole`: Prevents a console window from appearing when the application runs (use this if your application has a GUI or does not require a console). If it's a command-line application that needs a console, you might use `--console` or omit this flag.

    The executable will be created in a `dist` folder within your project directory.

## License

MIT