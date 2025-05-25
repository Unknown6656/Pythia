using System;
using System.Diagnostics;

namespace Pythia;


public sealed class PythiaInterface
{
    public static ConsoleColor ColorForeground = ConsoleColor.Gray;
    public static ConsoleColor ColorTitle = ConsoleColor.Cyan;


    public void Render()
    {
        UIRenderSize size = UIRenderSize.Compute();

        Console.HardResetAndFullClear();
        Console.CursorVisible = false;

        if (size.Window.Width < UIRenderSize.MinimumWindowSize.Width || size.Window.Height < UIRenderSize.MinimumWindowSize.Height)
            RenderInvalidSize(size);
        else
        {
            RenderFrame(size);

            // TODO : render everything else

            Console.CursorVisible = true;
        }
    }

    private void RenderFrame(UIRenderSize size)
    {
        Console.ForegroundColor = ColorForeground;

        Console.SetCursorPosition(0, 0);
        Console.Write($"┌{new string('─', size.Window.Width - 2)}┐");

        string line = $"│{new string(' ', size.Window.Width - 2)}│";

        for (int i = 1; i < size.Window.Height - 1; i++)
        {
            Console.SetCursorPosition(0, i);
            Console.Write(line);
        }

        Console.SetCursorPosition(0, size.Window.Height - 1);
        Console.Write($"└{new string('─', size.Window.Width - 2)}┘");

        Console.SetCursorPosition(0, size.VerticalSeparator.Y);
        Console.Write($"├{new string('─', size.Window.Width - 2)}┤");
        Console.WriteVertical($"┬{new string('│', size.VerticalSeparator.Height - 2)}┴", size.VerticalSeparator.X, size.VerticalSeparator.Y);
        Console.SetCursorPosition(size.Inspector.X, size.Inspector.Y);
        Console.Write($"├{new string('─', size.Inspector.Width - 2)}┤");
        Console.SetCursorPosition(size.Output.X, size.Output.Y);
        Console.Write($"├{new string('─', size.Output.Width - 2)}┤");

        Console.SetWindowFrameColor(ColorTitle);
        Console.SetCursorPosition(2, 0);
        Console.ForegroundColor = ColorTitle;
        Console.WriteBold(" PYTHIA Binary Reverse Engineering Tool | Unknown6656 ");

        Console.SetCursorPosition(1, 1);
        Console.Write($"{size.Window.Width} x {size.Window.Height}");
    }

    private void RenderInvalidSize(UIRenderSize size)
    {
        Console.BackgroundColor = ConsoleColor.DarkRed;
        Console.ForegroundColor = ConsoleColor.White;
        Console.FullClear();
        Console.SetCursorPosition(0, 1);
        Console.Write($"""
          ┌────────────────────────────────────────────┐
          │         ⚠️ ⚠️ WINDOW TOO SMALL ⚠️ ⚠️       │
          ├────────────────────────────────────────────┤
          │ Please resize the window to a minimum size │
          │ of {UIRenderSize.MinimumWindowSize.Width,3} x {UIRenderSize.MinimumWindowSize.Height,2}. The current window size is    │
          | {size.Window.Width,3} x {size.Window.Height,2}. You may alternatively reduce the │
          │ font size or the window's zoom factor.     │
          └────────────────────────────────────────────┘
        """);
    }

    public void ProcessConsoleInput(ConsoleKeyInfo key, out bool exit)
    {
        exit = false;
    }


    private sealed class UIRenderSize(
        int width,
        int height,
        int menu_height,
        int inspector_height,
        int code_height,
        int vert_separator_pos
    )
    {
        public static (int Width, int Height) MinimumWindowSize { get; } = (120, 50);


        public (int Width, int Height) Window => (width, height);
        public (int X, int Y, int Height) VerticalSeparator => (vert_separator_pos, menu_height, height - menu_height);
        public (int X, int Y, int Width, int Height) Menu => (0, 0, width, menu_height);
        public (int X, int Y, int Width, int Height) Binary => (0, menu_height, vert_separator_pos, height - menu_height - inspector_height);
        public (int X, int Y, int Width, int Height) Inspector => (0, height - inspector_height, vert_separator_pos + 1, inspector_height);
        public (int X, int Y, int Width, int Height) Code => (vert_separator_pos, menu_height, width - vert_separator_pos, code_height);
        public (int X, int Y, int Width, int Height) Output => (vert_separator_pos, menu_height + code_height, width - vert_separator_pos, height - menu_height - code_height);


        public static UIRenderSize Compute()
        {
            int width = Console.WindowWidth;
            int height = Console.WindowHeight;

            return new(
                width,
                height,
                menu_height: 3,
                inspector_height: 5,
                code_height: 20,
                width >> 1
            );
        }
    }
}


/* UI LAYOUT CONCEPT


            +-- TITLE ----------------------------------------------------------------------+   0
            |                                                                               |
            |  MENU BAND                                                                    |   menu_height
            |                                                                               |
            +--------------------------------------+-+------------------------------------+-+   vertical-separator-1
            |                                      |^|                                    |^|
            | BINARY DATA VIEWER                   | |  CODE INPUT WINDOW                 | |
            |                                      | |                                    | |
            |                                      | |                                    | |
            |                                      | |                                    | |   code-height
            |                                      | |                                    | |
            |                                      | |                                    | |
            |                                      | |                                    | |
            |                                      | |                                    | |
            |                                      | |                                    | | - binary-height
            |                                      | |                                    |v|
            |                                      | +------------------------------------+-+   vertical-separator-2
            |                                      | |                                    |^|
            |                                      | |  INTERPRETED DATA WINDOW           | |
            |                                      | |                                    | |
            |                                      | |                                    | |
            |                                      | |                                    | |
            |                                      | |                                    | |
            |                                      | |                                    | |
            |                                      | |                                    | |   data-height
            |                                      |v|                                    | |
            +--------------------------------------+-+                                    | | - vertical-separator-3
            |                                        |                                    | |
            |  INSPECTOR FOR THE CURRENT BINARY      |                                    | |
            |  DATA VIEWER CURSOR POSITION           |                                    | | - inspector-height
            |                                        |                                    | |
            |                                        |                                    |v|
            +----------------------------------------+------------------------------------+-+   window-height

            0                                        '- vert_separator_pos                  '- width

*/
