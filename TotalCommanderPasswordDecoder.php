////////////////////////////////////////////////////////////////////////////////
//
// Total Commander FTP Password Recovery Algorithm
//
// Bartosz Wójcik
// https://www.pelock.com
//
////////////////////////////////////////////////////////////////////////////////

class TotalCommanderPasswordDecoder
{
  private int $random_seed = 0;

  public static function hexstr2bytearray($str)
  {
    if (!is_string($str)) return false;

    $result = [];

    $len = strlen($str);

    if ($len == 0 || ($len & 1) != 0)
    {
      return false;
    }

    for ($i = 0; $i < $len; $i += 2)
    {
      $result[] = ( hexdec($str[$i]) << 4 ) | hexdec($str[$i + 1]);
    }

    return $result;
  }

  // initialize random generator with specified seed
  public function srand($seed)
  {
    $this->random_seed = $seed;
  }

  // generate pseudo-random number from the specified seed
  public function rand_max($nMax)
  {
    // cut numbers to 32 bit values (important)
    $this->random_seed = (( ($this->random_seed * 0x8088405) & 0xFFFFFFFF) + 1) & 0xFFFFFFFF;

    return ($this->random_seed * $nMax) >> 32;
  }

  // rotate bits left
  public static function rol8($var, $counter)
  {
    return (($var << $counter) | ($var >> (8 - $counter))) & 0xFF;
  }

  // decrypt Total Commander FTP password
  public function decryptPassword($password)
  {
    // convert hex string to array of integers
    $password_hex = static::hexstr2bytearray($password);

    // if the conversion failed - exit
    if (!$password_hex) return false;

    // number of converted bytes
    $password_length = count($password_hex);

    // length includes checksum at the end
    if ($password_length <= 4)
    {
      return false;
    }

    // minus checksum
    $password_length -= 4;

    $this->srand(849521);

    for ($i = 0; $i < $password_length; $i++)
    {
      $password_hex[ $i ] = static::rol8($password_hex[ $i ], $this->rand_max(8));
    }

    $this->srand(12345);

    for ($i = 0; $i < 256; $i++)
    {
      $x = $this->rand_max($password_length);
      $y = $this->rand_max($password_length);

      $c = $password_hex[ $x ];

      $password_hex[ $x ] = $password_hex[ $y ];
      $password_hex[ $y ] = $c;
    }

    $this->srand(42340);

    for($i = 0; $i < $password_length; $i++)
    {
      $password_hex[ $i ] ^= $this->rand_max(256);
    }

    $this->srand(54321);

    for ($i = 0; $i < $password_length; $i++)
    {
      $password_hex[ $i ] = ($password_hex[ $i ] - $this->rand_max(256)) & 0xFF;
    }

    // build final password
    $decoded_password = "";

    for($i = 0; $i < $password_length; $i++)
    {
      $decoded_password .= chr($password_hex[ $i ]);
    }

    return $decoded_password;
  }
}