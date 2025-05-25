using System.Threading.Tasks;
using System.Text.Json.Serialization;
using System.Text.Json;
using System.Text;
using System.IO;
using System;

using Unknown6656.Terminal;

namespace Pythia;


public static class Program
{
    public static bool IsRunning { get; private set; } = true;
    public static PythiaInterface Pythia { get; } = new();

    public static JsonSerializerOptions JSONSerializerOptions { get; } = new()
    {
        NewLine = "\n",
        IndentSize = 4,
        WriteIndented = true,
        PropertyNameCaseInsensitive = false,
        DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        AllowOutOfOrderMetadataProperties = true,
        AllowTrailingCommas = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        NumberHandling = JsonNumberHandling.AllowReadingFromString | JsonNumberHandling.AllowNamedFloatingPointLiterals,
        RespectNullableAnnotations = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip,
    };


    public static async Task Main(string[] argv)
    {
        ConsoleState state = Console.SaveConsoleState();
        Console.OutputEncoding = Encoding.UTF8;

        try
        {
            await using ConsoleResizeListener resize_listener = new();

            resize_listener.SizeChanged += (_, _, _, _) => Pythia.Render();
            resize_listener.Start();

            Pythia.Render();

            do
            {
                while (!Console.KeyAvailable)
                    await Task.Delay(100);

                ConsoleKeyInfo key = Console.ReadKey(true);

                Pythia.ProcessConsoleInput(key, out bool exit);

                IsRunning = !exit;
            }
            while (IsRunning);
        }
        finally
        {
            Console.RestoreConsoleState(state);
        }
    }
}

public record PythiaSettings
{
    public static PythiaSettings Default { get; } = new()
    {
    };

    // TODO: Add settings properties here


    public async Task SaveAsync(string path)
    {
        await using FileStream stream = new(path, FileMode.Create, FileAccess.Write, FileShare.Read);

        await JsonSerializer.SerializeAsync(stream, this, Program.JSONSerializerOptions);
    }

    public static async Task<PythiaSettings> LoadAsync(string path)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);

        return await JsonSerializer.DeserializeAsync<PythiaSettings>(stream, Program.JSONSerializerOptions) ?? Default;
    }
}
