class User < ActiveRecord::Base
  # Setup accessible (or protected) attributes for your model
  attr_accessible :id, :is_active, :email, :password, :password_confirmation, :username, :agree_to_terms
  attr_accessible :location, :image, :screen_name, :bio, :remove_image, :image_cache, :gender
  attr_accessible :dob, :total_points, :confirmed_at, :sign_in_count, :roles, :current_sign_in_at
  attr_accessible :app_role_ids, :institution_id, :is_verified, :artist_image, :artist_bio
  attr_accessible :remove_artist_image, :artist_image_cache, :slug, :total_flagged_count
  attr_accessible :current_flagged_count, :suspended_at, :suspended, :deleted, :deleted_at, :featured
  attr_accessible :beats_count, :tracks_count, :last_sign_in_at, :followers_count, :followed_users_count
  attr_accessible :remote_image_url, :confirmation_token, :reposts_count, :updated_at
  attr_accessible :newsletter_subscription, :social_accounts

  attr_accessor :login

  # extends and include
  extend RailsAdmin::GraphData
  extend PointsChecker
  extend FriendlyId
  include PublicActivity::Common
  include CustomPassword
  include ParseParams
  include RailsAdminCharts
  include SocialImage
  include RecommendationStrategy
  include SearchStrategy
  include FilterStrategy
  include Rails.application.routes.url_helpers
  include CustomProxyImage
  include SerializeObjects
  include CustomTimestamp

  # macros
  acts_as_liker
  acts_as_mentionable
  mount_uploader :image, PictureUploader
  mount_uploader :artist_image, PictureUploader
  devise :database_authenticatable, :registerable, :omniauthable, :confirmable,
         :recoverable, :rememberable, :trackable, :validatable
  friendly_id :generate_slug, use: :slugged

  # model constants
  ROLES = %w(Vocalist Producer Admin).freeze
  ADMIN_EMAILS = ['vibhor@trantorinc.com', 'rahul@speazie.com', 'sahil@speazie.com', 'b.wichmann@artemia.com', 'j.ogan@artemia.com', 'k.silva@artemia.com'].freeze

  # model validations
  validates :username, presence: true, length: { minimum: 3, maximum: 35 }
  validates_length_of :screen_name, in: 3..35, allow_blank: true
  validates :agree_to_terms, acceptance: { message: 'Please accept Terms and Conditions' }, on: :create
  validates :username, format: { with: /\A[a-zA-Z0-9_]+\Z/, message: :format }
  validates :username, uniqueness: { message: :taken }, unless: :destroyed?

  # Model Associations
  # user's whom i am follwoing
  has_many :relationships, foreign_key: 'follower_id', dependent: :destroy
  has_many :followed_users, through: :relationships, source: :followed
  has_many :unscoped_followed_users, -> { for_user_unscoped }, through: :relationships, source: :followed
  has_many :authentications, inverse_of: :user, dependent: :destroy
  # my followers
  has_many :reverse_relationships, foreign_key: 'followed_id', class_name:  'Relationship', dependent: :destroy
  has_many :followers, through: :reverse_relationships, source: :follower
  has_many :unscoped_followers, -> { for_user_unscoped }, through: :reverse_relationships, source: :follower
  has_many :beats, dependent: :destroy
  has_many :tracks, dependent: :destroy
  has_many :audios, dependent: :destroy
  has_many :user_tracings
  has_one  :notification_setting, inverse_of: :user, dependent: :destroy
  has_many :points_histories, -> { where target_type: 'User' }, foreign_key: 'target_id', dependent: :destroy
  # Taking alias because using roles below for roles_mask
  has_and_belongs_to_many :app_roles, class_name: 'Role'
  has_many :account_suspension_logs
  has_many :mentions, -> { where mentionable_type: 'User' }, class_name: 'Mention', foreign_key: :mentionable_id
  has_many :device_tokens, dependent: :destroy
  has_many :comments, dependent: :destroy
  has_many :tokens, dependent: :destroy
  has_and_belongs_to_many :genres
  belongs_to :institution
  has_many :contest_users
  has_many :contests, through: :contest_users
  has_many :my_contests, class_name: 'Contest', foreign_key: 'owner_id', inverse_of: :owner, dependent: :destroy
  has_many :reposts, dependent: :destroy
  has_many :reposted_songs, -> { audio_default_scope }, through: :reposts, source: :audio, class_name: 'V1::Audio', dependent: :destroy
  has_many :likes, foreign_key: 'liker_id'

  accepts_nested_attributes_for :authentications

  # Callbacks
  before_save :update_deactivate_user, :update_slug
  after_create :create_notification_setting, :update_points, :strip_whitespace
  after_save :reset_featured_artists

  # Scopes
  default_scope { where(is_active: true, suspended: false, deleted: false) }
  scope :search_user, ->(user_name) { where('users.username like ? OR users.screen_name like ?', "#{user_name}%", "#{user_name}%").order('users.username').select_user_fields }
  scope :all_users, ->(logged_user) { where.not(id: logged_user.id) }
  scope :except_users, ->(user_ids) { where('users.id NOT IN (?)', user_ids) }
  scope :for_user_unscoped, -> { unscope(where: [:is_active, :deleted, :suspended]) }
  scope :popular, -> { order('total_points DESC') }
  scope :featured_artists, -> { where(featured: true) }
  scope :select_user_fields, -> { select('users.id, users.username, users.screen_name, users.image, users.updated_at, users.location, users.is_verified') }
  scope :user_worker_fields, -> { select(:id, :email, :username, :screen_name) }
  scope :search_priority, ->(relationships) { order(build_searching_order(relationships)) }
  scope :tagging, ->(current_user, keyword) { all_users(current_user).where('username like ?', "#{keyword}%").order('username').select_user_fields.limit(TAGGING_RESULTS) }
  serialize :social_accounts, Hash

  def search_with_order(search, relationships)
    User.search_priority(relationships).search_user(search)
  end

  # Instance Methods
  def roles=(roles)
    if roles.present?
      roles = roles.is_a?(Array) ? roles : roles.split # Used for rails admin role
      self.roles_mask = (roles & ROLES).map { |r| 2**ROLES.index(r) }.inject(0, :+)
    end
  end

  def roles
    ROLES.reject do |r|
      ((roles_mask.to_i || 0) & 2**ROLES.index(r)).zero?
    end
  end

  def following?(other_user)
    relationships.find_by(followed_id: other_user.id).present?
  end

  def update_sign_details(suspended = false)
    if suspended
      update(sign_in_count: sign_in_count + 1, current_sign_in_at: Time.now, suspended: false, suspended_at: nil)
      show_user_data
    else
      update(sign_in_count: sign_in_count + 1, current_sign_in_at: Time.now)
    end
  end

  def leaders
    Rails.cache.fetch("#{id}-followed_users", expires_in: 30.minutes) do
      unscoped_followed_users.select_user_fields.order('relationships.id DESC')
    end
  end

  def leader_ids
    Rails.cache.fetch("#{id}-followed_users_ids", expires_in: 30.minutes) do
      followed_users.pluck(:id)
    end
  end

  # To search user based on search keyword and by following strategies
  # Then will filter result and return some limit of users currently its 15
  def recommended_users
    strategies = [:leaderboard_toppers, :trending_users]
    tmp_users = []
    following_ids = leader_ids
    users = strategies.map do |strategy|
      result_users = send(strategy, (tmp_users.collect(&:id) + following_ids + [id])).sample(RECOMMENDED_USERS_COUNT)
      tmp_users += result_users
      result_users.flatten
    end
    filter_engine(users, RECOMMENDED_USERS_RANGES, RECOMMENDED_USERS_COUNT)
  end

  # To return search users list
  # based on the search keyword
  def search_users(search)
    strategies = [:following_users, :friends_friends, :default]
    except_users = []
    strategies.map do |strategy|
      result_users = send(strategy, search, (except_users.collect(&:id) << id))
      except_users += result_users
      result_users
    end.flatten
  end

  def follow!(other_user)
    relationships.create!(followed_id: other_user.id)
  end

  def unfollow!(other_user)
    relationships.find_by(followed_id: other_user.id).destroy
  rescue
    nil
  end

  def points
    total_points
  end

  def filter_my_tracks_beats(params)
    if params[:type].present?
      songs_type = params[:type]
    else
      if beats_count == 0
        if tracks_count == 0 & reposts_count > 0
          songs_type = 'Repost'
        elsif tracks_count > 0
          songs_type = 'Track'
        end
      else
        songs_type = 'Beat'
      end
    end
    case songs_type
    when 'Track'
      tracks.includes(:likes, :user).order(id: :desc).page(params[:page])
    when 'Repost'
      reposted_songs.includes(:likes, :user).order(id: :desc).page(params[:page])
    else
      beats.includes(:likes, :user).order(id: :desc).page(params[:page])
    end
  end

  # to store user location info, device info while login.
  def trace_user(user_agent, location, ip_address)
    Warden::Manager.after_set_user except: :fetch do
      user_tracing = user_tracings.where(ip_address: ip_address, user_agent: user_agent).first
      # if already login using same ip and same device
      if user_tracing
        user_tracing.sign_out_at = nil
        user_tracing.save
      else
        # first time user sign in
        user_tracing = user_tracings.build
        location_details = location && location.data ? location.data : nil
        user_tracing.save_attributes(ip_address, current_sign_in_at, user_agent, location_details)
      end
    end
  end

  def update_traced_user(user_agent, ip_address)
    # updating sign out time just before user logs out
    Warden::Manager.before_logout do
      user_tracing = user_tracings.where(user_agent: user_agent, ip_address: ip_address).first
      user_tracing.update_attribute(:sign_out_at, Time.now) if user_tracing
    end
  end

  def admin?
    app_roles.pluck(:name).include?('admin') || is_admin?
  end

  def custom_label_method
    username
  end

  def serialize_user
    serializable_hash(only: :[:id, :username, :gender]).merge(image: { medium: proxy_image_url, thumb: proxy_image_url('thumb') })
  end

  def create_notification_setting
    NotificationSetting.create(user_id: id)
  end

  def following_or_follows?(recipient_id)
    follows_and_follower_ids = following_and_followers_ids
    follows_and_follower_ids.include?(recipient_id)
  end

  def update_points
    update(total_points: USER_CREATION_POINTS)
    PointsHistory.create_points_history(total_points, POINT_ACTIONS[:user_create], id, USER_CREATION_POINTS, self.class.name)
  end

  def following_and_followers_ids
    followers.pluck(:id) + leader_ids
  end

  def user_i_am_following
    followed_users.pluck(:id)
  end

  def find_level
    case points
    when BAND_CAMPER
      BAND_CAMPER_LABEL
    when JAM_MASTER
      JAM_MASTER_LABEL
    when HEAD_BANGER
      HEAD_BANGER_LABEL
    when ROLLING_STONE
      ROLLING_STONE_LABEL
    end
  end

  def strip_whitespace
    self.username = username.strip if username
    self.screen_name = screen_name.strip if screen_name
    self.email = email.strip if email
  end

  def is_admin?
    ADMIN_EMAILS.include?(email)
  end

  # to get beats and tracks count a user
  # this will return like {"Beat"=>7, "Track"=>5}
  def beats_and_tracks_count
    counts = Audio.group('type').where(user_id: id).count
    return counts unless counts.blank?
    { 'Beat' => 0, 'Track' => 0 }
  end

  def mixpanel_registration(provider = 'email')
    MixpanelWorker.perform_async(user_id: id, event: REG_MIXPANEL_EVENT, provider: provider)
  end

  def build_user_attributes(auth, force_confirm = true)
    self.password = generate_password
    self.password_confirmation = password
    self.email = auth[:info][:email] || '' if email.blank?
    self.username = auth[:info][:username] || auth[:uid]
    self.screen_name = auth[:extra][:raw_info][:name]
    if force_confirm
      self.confirmed_at = Time.now
      self.confirmation_token = nil
    end
    self.gender = auth[:extra][:raw_info][:gender] if auth[:extra][:raw_info][:gender]
    self.dob = auth[:extra][:raw_info][:dob] if auth[:extra][:raw_info][:dob]
    self.bio = auth[:extra][:raw_info][:bio] if auth[:extra][:raw_info][:bio]
    if auth[:info][:image]
      self.remote_image_url = profile_image(auth[:info][:image], auth[:provider])
    end
    self
  end

  def filter_user_points(params)
    time_query = set_date params
    target_type = 'User'
    order_by = 'id DESC'
    points = PointsHistory.user_points target_type, id, time_query, order_by
    [points, points.collect(&:total).inject(:+)]
  end

  def generate_slug
    username
  end

  def update_deactivate_user
    if changed.include?('is_active')
      if is_active?
        show_user_data
      else
        hide_user_data
        UserMailer.notify_user_deactivation(self).deliver_later unless new_record?
      end
    end
  end

  def hide_user_data
    activate_in_active_user_data(false)
    device_tokens.destroy_all
    tokens.destroy_all
  end

  def show_user_data
    activate_in_active_user_data
  end

  def activate_in_active_user_data(active = true)
    Audio.unscoped.where(user_id: id).update_all(active: active)
  end

  def update_flagged_count(count = 1)
    self.total_flagged_count += count
    self.current_flagged_count += count unless suspended?
    if !suspended? && self.current_flagged_count == FLAGGED_COUNT
      self.suspended = true
      self.suspended_at = Time.now
      self.current_flagged_count = 0
      AccountSuspensionLog.create(user_id: id)
      hide_user_data
      UserMailer.notify_suspended_user(self).deliver_later
    elsif count == -1 && suspended?
      self.suspended = false
      self.suspended_at = nil
      self.current_flagged_count = 2
      AccountSuspensionLog.where(user_id: id).last.destroy
      show_user_data
    end
    save
  end

  def max_suspension_time
    suspended_at + SUSPENDED_DAYS.days
  end

  def remove_suspension
    update(suspended: false, suspended_at: nil)
    show_user_data
  end

  def create_auth_token
    Token.create(user_id: id).auth_token
  end

  def destroy
    run_callbacks :destroy do
      tmp_password = generate_password
      update(deleted: 1, deleted_at: Time.now, password: tmp_password, password_confirmation: tmp_password)
    end
  end

  # to overide default destroyed? method for soft delete check
  def destroyed?
    deleted
  end

  def cached_genres
    Rails.cache.fetch("#{id}-genres", expires_in: 30.days) do
      genres.pluck(:id)
    end
  end

  def reset_featured_artists
    Rails.cache.delete('featured_artists') if changed.include?('featured')
  end

  def update_slug
    self.slug = username if changed.include?('username')
  end

  def reset_session
    ResetSessionWorker.perform_async(id)
    UserMailer.password_change_confirmation(self).deliver_later
  end

  # Class methods
  class << self
    def proxy_image_url(user_id, format = 'medium', _api = true, _version = 'v2')
      Rails.application.routes.url_helpers.image_api_user_url(id: user_id, type: format)
    end

    def update_points(user_id, points, action, action_user, force_update = false)
      return if not_update_points?(action, user_id, action_user) && !force_update
      user = User.find(user_id)
      user.update(total_points: user.total_points + points)
      PointsHistory.create_points_history(user.total_points, action, user.id, points, user.class.name)
    end

    def search(params, user)
      return user.leader_ids << user.id if params[:criteria] == 'circle'
      User.where('location = ?', user.location).pluck(:id)
    end

    def find_level(points)
      case points
      when BAND_CAMPER
        BAND_CAMPER_LABEL
      when JAM_MASTER
        JAM_MASTER_LABEL
      when HEAD_BANGER
        HEAD_BANGER_LABEL
      when ROLLING_STONE
        ROLLING_STONE_LABEL
      end
    end

    def available?(query)
      User.where(query).first.present? ? false : true
    end

    def users_list(users)
      users_list = []
      users.each do |user|
        users_list << user_detail(user)
      end
      users_list
    end

    def user_detail(user)
      user_detail = { id: user.id, username: user.username, email: user.email }
      user_detail[:bio] = user.bio ? user.bio : ''
      user_detail[:screen_name] = user.screen_name ? user.screen_name : user.username
      user_detail[:location] = user.location ? user.location : ''
      user_detail[:image] = { medium: user.proxy_image_url, thumb: user.proxy_image_url('thumb') }
      user_detail[:roles] = user.roles ? user.roles : ''
      user_detail[:gender] = user.gender ? user.gender : ''
      user_detail[:dob] = user.dob ? user.dob : ''
      user_detail[:points] = user.points
      user_detail[:sign_in_count] = user.sign_in_count
      user_institution = user.institution
      if user_institution
        user_detail[:institution] = {}
        user_detail[:institution][:name] = ''
        user_detail[:institution][:bg_color] = ''
        user_detail[:institution][:text_color] = ''
      end
      user_detail
    end

    def find_first_by_auth_conditions(warden_conditions)
      conditions = warden_conditions.dup
      if login = conditions.delete(:login)
        where(conditions).where(['lower(username) = :value OR lower(email) = :value', { value: login.downcase }]).first
      else
        where(conditions).first
      end
    end

    def find_for_database_authentication(options = {})
      where(['lower(username) = :value OR lower(email) = :value', { value: options[:login].try(:downcase) }]).first
    end

    def build_searching_order(relationships)
      orders = [:friends_friend, :following]
      order_clause = 'CASE'
      leaders_id = relationships.map(&:followed_id)
      second_hop_leaders_id = Relationship.where(follower_id: leaders_id).pluck(:followed_id).uniq
      second_hop_leaders_id -= leaders_id
      orders.each_with_index do |priority, index|
        if priority == :following
          order_clause << sanitize_sql_array([' WHEN users.id in (?) THEN ? ', leaders_id, index])
        elsif priority == :friends_friend
          order_clause << sanitize_sql_array([' WHEN users.id in (?) THEN ? ', second_hop_leaders_id, index])
        end
      end
      order_clause << ' END DESC'
    end
  end

  def send_devise_notification(notification, *args)
    devise_mailer.send(notification, self, *args).deliver_later
  end

  def after_confirmation
    FollowSpeazieWorker.perform_async(self.class.id)
  end
end
