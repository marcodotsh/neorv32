-- The NEORV32 RISC-V Processor - github.com/stnolting/neorv32
-- Auto-generated RSA public key initialization image (for secure boot checker)
-- Built: 26.07.2025 14:42:58

library ieee;
use ieee.std_logic_1164.all;

library neorv32;
use neorv32.neorv32_package.all;

package neorv32_secure_boot_checker_verification_image is

  constant rsa_modulus_c : std_ulogic_vector(287 downto 0) := x"F544B3A3926CB059292C3EED44644884C9273ED6E7DD97A2314EDB3BF1DDD2E1C6927C3F";
  constant rsa_public_exponent_c : std_ulogic_vector(19 downto 0) := x"10001";
end neorv32_secure_boot_checker_verification_image;
