library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

library neorv32;
use neorv32.neorv32_package.all;
use neorv32.neorv32_bootloader_image.all;
use neorv32.neorv32_secure_boot_sha256_package.all;

entity neorv32_secure_boot_boot_rom_hasher is
  generic (
    RESET_VALUE : std_ulogic := '0'
  );
  port (
    clk_i           : in std_ulogic; -- global clock line
    rst_i           : in std_ulogic; -- async reset, low-active
    start_i         : in std_ulogic; -- start signal
    words_to_read_i : in std_ulogic_vector(31 downto 0); -- 32-bit words to read from boot rom
    bus_rsp_i       : in bus_rsp_t; -- bus response
    bus_req_o       : out bus_req_t; -- bus request
    done_o          : out std_ulogic; -- done signal
    hash_o          : out std_ulogic_vector((WORD_SIZE * 8) - 1 downto 0) -- hash result
  );
end entity;

architecture neorv32_secure_boot_boot_rom_hasher_rtl of neorv32_secure_boot_boot_rom_hasher is
  type state_t is (
    RESET,
    IDLE,
    CHECK_INPUT_END,
    MEM_REQ,
    MEM_READ,
    CHECK_FULL_BLOCK,
    SEND_BLOCK,
    CHECK_PROGRESS,
    PAD_ONE_BIT,
    CHECK_LAST_BLOCK,
    SEND_BLOCK_AFTER_PAD,
    CHECK_PROGRESS_AFTER_PAD,
    ADD_TAIL,
    DONE_STATE
  );
  signal CURRENT_STATE, NEXT_STATE : state_t;

  -- counters
  constant words_in_block_count_limit_c : std_ulogic_vector(8 downto 0)  := std_ulogic_vector(to_unsigned(16, 9));
  signal words_in_block_counter_reg     : std_ulogic_vector(8 downto 0)  := (others => '0');
  signal blocks_counter_reg             : std_ulogic_vector(31 downto 0) := (others => '0');

  -- output signals
  signal bus_req_reg : bus_req_t;
  signal done_reg    : std_ulogic;

  -- internal signals
  signal addr_reg               : std_ulogic_vector(31 downto 0) := (others => '0');
  signal read_data_reg          : std_ulogic_vector(31 downto 0);
  signal read_data_reverse_wire : std_ulogic_vector(31 downto 0);
  signal hash_tail_wire         : std_ulogic_vector(63 downto 0); -- size of the bootloader to write in last padded block
  type msg_block_array_t is array (0 to 15) of std_ulogic_vector(WORD_SIZE - 1 downto 0);
  signal msg_block_buf_reg  : msg_block_array_t;
  signal msg_block_buf_wire : std_ulogic_vector(0 to 16 * WORD_SIZE - 1);

  -- signals from sha256 core
  signal block_waiting_wire : std_ulogic;
  signal block_process_wire : std_ulogic;
  signal finished_wire      : std_ulogic;

  -- signals to sha256 core
  signal block_valid_reg : std_ulogic;
  signal n_blocks_wire   : std_ulogic_vector(31 downto 0);

begin

  sha256_core : entity neorv32.neorv32_secure_boot_sha256_core
    port map
    (
      clk_i           => clk_i,
      rst_i           => rst_i,
      block_waiting_o => block_waiting_wire,
      block_valid_i   => block_valid_reg,
      block_process_o => block_process_wire,
      n_blocks_i      => n_blocks_wire,
      msg_block_i     => msg_block_buf_wire,
      done_o          => finished_wire,
      data_o          => hash_o
    );

  gen_read_reverse_wire_i : for i in 0 to 3 generate
    gen_read_reverse_wire_j : for j in 0 to 7 generate
      read_data_reverse_wire(8 * i + j) <= read_data_reg(8 * i + (7 - j));
    end generate;
  end generate;

  gen_block_buf_wire_i : for i in 0 to 15 generate
    gen_block_buf_wire_j : for j in 0 to WORD_SIZE - 1 generate
      msg_block_buf_wire(WORD_SIZE * i + j) <= msg_block_buf_reg(i)(j);
    end generate;
  end generate;

  --change state logic
  process (clk_i, rst_i)
  begin
    if (rst_i = RESET_VALUE) then
      CURRENT_STATE <= RESET;
    elsif (rising_edge(clk_i)) then
      CURRENT_STATE <= NEXT_STATE;
    end if;
  end process;

  --next state logic
  process (CURRENT_STATE, rst_i, start_i, bus_rsp_i, words_in_block_counter_reg, block_waiting_wire, block_process_wire, addr_reg, words_to_read_i, blocks_counter_reg, n_blocks_wire)
  begin
    case CURRENT_STATE is
      when RESET =>
        if (rst_i = RESET_VALUE) then
          NEXT_STATE <= RESET;
        else
          NEXT_STATE <= IDLE;
        end if;
      when IDLE =>
        if start_i = '1' then
          NEXT_STATE <= CHECK_INPUT_END;
        else
          NEXT_STATE <= IDLE;
        end if;
      when CHECK_INPUT_END =>
        if shift_right(unsigned(addr_reg), 2) = unsigned(words_to_read_i) then
          NEXT_STATE <= PAD_ONE_BIT;
        else
          NEXT_STATE <= MEM_REQ;
        end if;
      when MEM_REQ =>
        NEXT_STATE <= MEM_READ;
      when MEM_READ =>
        if bus_rsp_i.ack = '1' then
          NEXT_STATE <= CHECK_FULL_BLOCK;
        else
          NEXT_STATE <= MEM_READ;
        end if;
      when CHECK_FULL_BLOCK =>
        if (unsigned(words_in_block_counter_reg) = (unsigned(words_in_block_count_limit_c) - 1)) then
          NEXT_STATE <= SEND_BLOCK;
        else
          NEXT_STATE <= CHECK_INPUT_END;
        end if;
      when SEND_BLOCK =>
        if (block_waiting_wire = '1') then
          NEXT_STATE <= CHECK_PROGRESS;
        else
          NEXT_STATE <= SEND_BLOCK;
        end if;
      when CHECK_PROGRESS =>
        if (block_process_wire = '1') then
          if unsigned(blocks_counter_reg) = unsigned(n_blocks_wire) then
            NEXT_STATE <= DONE_STATE;
          else
            NEXT_STATE <= CHECK_INPUT_END;
          end if;
        else
          NEXT_STATE <= CHECK_PROGRESS;
        end if;
      when PAD_ONE_BIT =>
        NEXT_STATE <= CHECK_LAST_BLOCK;
      when CHECK_LAST_BLOCK =>
        if unsigned(blocks_counter_reg) = unsigned(n_blocks_wire) - 1 then
          NEXT_STATE <= ADD_TAIL;
        else
          NEXT_STATE <= SEND_BLOCK_AFTER_PAD;
        end if;
      when SEND_BLOCK_AFTER_PAD =>
        if (block_waiting_wire = '1') then
          NEXT_STATE <= CHECK_PROGRESS_AFTER_PAD;
        else
          NEXT_STATE <= SEND_BLOCK_AFTER_PAD;
        end if;
      when CHECK_PROGRESS_AFTER_PAD =>
        if (block_process_wire = '1') then
          if unsigned(blocks_counter_reg) = unsigned(n_blocks_wire) then
            NEXT_STATE <= DONE_STATE;
          else
            NEXT_STATE <= ADD_TAIL;
          end if;
        else
          NEXT_STATE <= CHECK_PROGRESS_AFTER_PAD;
        end if;
      when ADD_TAIL =>
        NEXT_STATE <= SEND_BLOCK;
      when DONE_STATE =>
        NEXT_STATE <= DONE_STATE;
    end case;
  end process;

  --output and register logic
  process (clk_i, rst_i)
  begin
    if (rst_i = RESET_VALUE) then
      bus_req_reg                <= req_terminate_c;
      done_reg                   <= '0';
      addr_reg                   <= (others => '0');
      read_data_reg              <= (others => '0');
      block_valid_reg            <= '0';
      msg_block_buf_reg          <= (others => (others => '0'));
      words_in_block_counter_reg <= (others => '0');
      blocks_counter_reg         <= (others => '0');
    elsif (rising_edge(clk_i)) then
      case CURRENT_STATE is
        when RESET =>
          bus_req_reg                <= req_terminate_c;
          done_reg                   <= '0';
          addr_reg                   <= (others => '0');
          read_data_reg              <= (others => '0');
          block_valid_reg            <= '0';
          msg_block_buf_reg          <= (others => (others => '0'));
          words_in_block_counter_reg <= (others => '0');
          blocks_counter_reg         <= (others => '0');
        when IDLE                             =>
          bus_req_reg       <= req_terminate_c;
          done_reg          <= '0';
          addr_reg          <= (others => '0');
          read_data_reg     <= (others => '0');
          block_valid_reg   <= '0';
          msg_block_buf_reg <= (others => (others => '0'));
        when CHECK_INPUT_END =>
          null;
        when MEM_REQ =>
          bus_req_reg.addr  <= std_ulogic_vector(unsigned(base_io_bootrom_c) + unsigned(addr_reg));
          bus_req_reg.data  <= (others => '0');
          bus_req_reg.ben   <= (others => '1');
          bus_req_reg.stb   <= '1';
          bus_req_reg.rw    <= '0';
          bus_req_reg.src   <= '0';
          bus_req_reg.priv  <= '0';
          bus_req_reg.debug <= '0';
          bus_req_reg.amo   <= '0';
          bus_req_reg.amoop <= (others => '0');
          bus_req_reg.burst <= '0';
          bus_req_reg.lock  <= '0';
          bus_req_reg.fence <= '0';
        when MEM_READ =>
          if bus_rsp_i.ack = '1' then
            bus_req_reg.stb <= '0';
            read_data_reg   <= std_ulogic_vector(bus_rsp_i.data);
          end if;
        when CHECK_FULL_BLOCK =>
          addr_reg <= std_ulogic_vector(unsigned(addr_reg) + 4);
          for i in 0 to 3 loop
            for j in 0 to 7 loop
              msg_block_buf_reg(to_integer(unsigned(words_in_block_counter_reg))) <= read_data_reverse_wire;
            end loop;
          end loop;
          if (unsigned(words_in_block_counter_reg) = unsigned(words_in_block_count_limit_c) - 1) then

          else
            words_in_block_counter_reg <= std_ulogic_vector(unsigned(words_in_block_counter_reg) + 1);
          end if;
        when SEND_BLOCK =>
          if (block_waiting_wire = '1') then
            block_valid_reg    <= '1';
            blocks_counter_reg <= std_ulogic_vector(unsigned(blocks_counter_reg) + 1);
          end if;
        when CHECK_PROGRESS =>
          block_valid_reg <= '0';
          if (block_process_wire = '1') then
            words_in_block_counter_reg <= (others => '0');
            msg_block_buf_reg          <= (others => (others => '0')); -- Clear buffer after processing
          end if;
        when PAD_ONE_BIT =>
          msg_block_buf_reg(to_integer(unsigned(words_in_block_counter_reg)))(0) <= '1';
        when CHECK_LAST_BLOCK =>
          null;
        when SEND_BLOCK_AFTER_PAD =>
          if (block_waiting_wire = '1') then
            block_valid_reg    <= '1';
            blocks_counter_reg <= std_ulogic_vector(unsigned(blocks_counter_reg) + 1);
          end if;
        when CHECK_PROGRESS_AFTER_PAD =>
          block_valid_reg <= '0';
          if (block_process_wire = '1') then
            words_in_block_counter_reg <= (others => '0');
            msg_block_buf_reg          <= (others => (others => '0')); -- Clear buffer after processing
          end if;
        when ADD_TAIL =>
          for i in 0 to 63 loop
            msg_block_buf_reg(14 + i / 32)(i mod 32) <= hash_tail_wire(63 - i);
          end loop;
        when DONE_STATE =>
          bus_req_reg.stb <= '0';
          if finished_wire = '1' then
            done_reg <= '1';
          end if;
      end case;
    end if;
  end process;

  bus_req_o      <= bus_req_reg;
  done_o         <= done_reg;
  n_blocks_wire  <= std_ulogic_vector(shift_right(unsigned(words_to_read_i) + to_unsigned(2, words_to_read_i'length), 4) + to_unsigned(1, words_to_read_i'length)); --padded blocks to hash
  hash_tail_wire <= std_ulogic_vector(shift_left(resize(unsigned(words_to_read_i), 64), 5)); --bit from 32 bit words

end architecture;
