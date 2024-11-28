defmodule FiddlerTest do
  use ExUnit.Case
  doctest Fiddler

  test "greets the world" do
    assert Fiddler.hello() == :world
  end
end
