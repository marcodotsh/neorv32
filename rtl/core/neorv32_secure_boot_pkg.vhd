library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

library neorv32;
use neorv32.neorv32_package.all;

package neorv32_secure_boot_pkg is

  -- function to initialize the secure boot ROM
  function secure_boot_init_f(
    bootloader_image : mem32_t;
    secure_info      : mem32_t;
    rom_size         : natural
  ) return mem32_t;

end neorv32_secure_boot_pkg;

package body neorv32_secure_boot_pkg is

  function secure_boot_init_f(
    bootloader_image : mem32_t;
    secure_info      : mem32_t;
    rom_size         : natural
  ) return mem32_t is
    variable result : mem32_t(0 to rom_size - 1);
  begin
    -- initialize the whole ROM with zeros
    for j in 0 to rom_size - 1 loop
      result(j) := (others => '0');
    end loop;

    -- copy the bootloader image to the beginning of the ROM
    for k in bootloader_image'range loop
      if k < rom_size then
        result(k) := bootloader_image(k);
      end if;
    end loop;

    -- copy the secure boot info (signature and length) to the end of the ROM
    for l in secure_info'range loop
      if (rom_size - secure_info'length + l) < rom_size then
        result(rom_size - secure_info'length + l) := secure_info(l);
      end if;
    end loop;

    return result;
  end function;

end neorv32_secure_boot_pkg;
