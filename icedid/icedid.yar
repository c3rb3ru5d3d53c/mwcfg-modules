rule IcedID
{
  strings:
      $obfCode = {8A 44 11 40 32 04 11 88 44 0D 07 48 FF C1}
  condition:
      all of them
}